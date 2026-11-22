import os
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6 import QtWidgets

import controller.controller as controller_module

# Stands in for nmap: echoes its arguments and writes the -oA files with one open port for the target.
FAKE_NMAP = '''#!/usr/bin/env python3
import sys
args = sys.argv[1:]
print("fake nmap args: " + " ".join(args))
out = args[args.index("-oA") + 1] if "-oA" in args else None
target = [a for a in args if a.startswith("10.")][-1]
xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap" start="1700000000" startstr="x" version="7.95" xmloutputversion="1.05">
<host starttime="1700000000" endtime="1700000001"><status state="up" reason="syn-ack"/>
<address addr="%s" addrtype="ipv4"/><hostnames/>
<ports><port protocol="tcp" portid="3000"><state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="ppp" method="table" conf="3"/></port></ports>
</host><runstats><finished time="1700000001" timestr="x" elapsed="1" exit="success"/>
<hosts up="1" down="0" total="1"/></runstats></nmaprun>
""" % target
if out:
    for ext in ("xml", "nmap", "gnmap"):
        with open(out + "." + ext, "w") as handle:
            handle.write(xml if ext == "xml" else "fake\\n")
print("Nmap done: 1 IP address (1 host up)")
'''


class NmapCommandBarTest(unittest.TestCase):
    """Drives the nmap command bar of the real desktop Controller/View offscreen, with a stand-in nmap."""

    @classmethod
    def setUpClass(cls):
        cls._qt_app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="legion-nmapbar-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        fake_bin = os.path.join(self.tmp, "bin")
        os.makedirs(fake_bin)
        fake_nmap = os.path.join(fake_bin, "nmap")
        with open(fake_nmap, "w", encoding="utf-8") as handle:
            handle.write(FAKE_NMAP)
        os.chmod(fake_nmap, 0o755)
        env = patch.dict(os.environ, {
            "LEGION_HOME": self.tmp,
            "PATH": fake_bin + os.pathsep + os.environ.get("PATH", ""),
        })
        env.start()
        self.addCleanup(env.stop)
        import app.ProjectManager as pm_module
        temp_dir = patch.object(pm_module, "tempDirectory", self.tmp)
        temp_dir.start()
        self.addCleanup(temp_dir.stop)
        # ViewState.hostTabs is a class-level dict: without this, tool tabs leak from one test's window to the next.
        from ui.ViewState import ViewState
        host_tabs = patch.object(ViewState, "hostTabs", {})
        host_tabs.start()
        self.addCleanup(host_tabs.stop)

    def _build(self, hosts=("10.0.0.5", "10.0.0.9")):
        from app.ProjectManager import ProjectManager
        from app.logging.legionLog import getAppLogger, getDbLogger
        from app.logic import Logic
        from app.shell.DefaultShell import DefaultShell
        from app.tools.ToolCoordinator import ToolCoordinator
        from app.tools.nmap.DefaultNmapExporter import DefaultNmapExporter
        from db.RepositoryFactory import RepositoryFactory
        from db.entities.host import hostObj
        from ui.ViewState import ViewState
        from ui.gui import Ui_MainWindow
        from ui.view import View

        main_window = QtWidgets.QMainWindow()
        self._qt_refs = [main_window]
        ui = Ui_MainWindow()
        ui.setupUi(main_window)
        shell = DefaultShell()
        project_manager = ProjectManager(shell, RepositoryFactory(getDbLogger()), getAppLogger())
        logic = Logic(shell, project_manager,
                      ToolCoordinator(shell, DefaultNmapExporter(shell, getAppLogger())))
        logic.createNewTemporaryProject()
        view = View(ViewState(), ui, main_window, shell, self._qt_app, None)
        self._qt_refs.extend((ui, view, logic))
        self.addCleanup(self._teardown, main_window, view, logic)
        ctrl = controller_module.Controller(view, logic)
        self._qt_refs.append(ctrl)

        if hosts:
            session = logic.activeProject.database.session()
            for ip in hosts:
                session.add(hostObj(ip=ip, ipv4=ip, hostname=""))
            session.commit()
            session.close()
            view.updateInterface()
            self._qt_app.processEvents()
        return ctrl, view

    def _teardown(self, main_window, view, logic):
        from ui.qt_shutdown import destroy_main_window

        ctrl = getattr(view, "controller", None)
        for timer in (getattr(ctrl, "updateUITimer", None), getattr(ctrl, "updateUI2Timer", None),
                      getattr(ctrl, "processTableUiUpdateTimer", None),
                      getattr(view, "_notes_autosave_timer", None)):
            if timer is not None:
                timer.stop()
        view._app_exit_in_progress = True
        if ctrl is not None and hasattr(ctrl, "processTableUiUpdateTimer"):
            ctrl.closeProject()
        else:
            logic.activeProject.database.dispose()
        self._qt_refs.clear()
        destroy_main_window(main_window, self._qt_app)

    def _select(self, view, ip):
        view.ui.HostsTableView.selectRow(view.HostsTableModel.getRowForIp(ip))
        view.hostTableClick()
        self._qt_app.processEvents()

    def _wait_for(self, condition, timeout=20.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            self._qt_app.processEvents()
            if condition():
                return True
            time.sleep(0.02)
        return False

    def _tab_titles(self, view):
        tabs = view.ui.ServicesTabWidget
        return [tabs.tabText(i) for i in range(tabs.count())]

    def _ports(self, ctrl, ip):
        ports = ctrl.logic.activeProject.repositoryContainer.portRepository.getPortsByIPAndProtocol(ip, "tcp")
        return [str(p) for p in ports] if ports else []

    def test_bar_is_disabled_until_a_host_is_selected(self):
        ctrl, view = self._build(hosts=())
        self.assertEqual("no host selected", view.ui.NmapCommandTargetLabel.text())
        self.assertFalse(view.ui.NmapCommandRunButton.isEnabled())

        started, message = ctrl.runNmapCommand(view.nmapCommandBarTarget(), "-sV")

        self.assertFalse(started)
        self.assertEqual("Select a host first.", message)
        self.assertNotIn("custom scan", self._tab_titles(view))

    def test_target_follows_the_selected_host(self):
        _ctrl, view = self._build()
        self._select(view, "10.0.0.9")
        self.assertEqual("10.0.0.9", view.nmapCommandBarTarget())
        self.assertIn("10.0.0.9", view.ui.NmapCommandTargetLabel.text())
        self.assertTrue(view.ui.NmapCommandRunButton.isEnabled())

        self._select(view, "10.0.0.5")
        self.assertEqual("10.0.0.5", view.nmapCommandBarTarget())
        self.assertIn("10.0.0.5", view.ui.NmapCommandTargetLabel.text())

    def test_enter_runs_the_typed_options_against_the_selected_host_and_imports_the_result(self):
        ctrl, view = self._build()
        self._select(view, "10.0.0.9")
        marker = os.path.join(self.tmp, "marker")

        view.ui.NmapCommandInput.setEditText(f"-sV -p 3000; touch {marker}")
        view.ui.NmapCommandInput.lineEdit().returnPressed.emit()

        self.assertEqual("custom scan", view.ui.ServicesTabWidget.tabText(view.ui.ServicesTabWidget.currentIndex()))
        output_box = view.ui.ServicesTabWidget.currentWidget().findChild(QtWidgets.QPlainTextEdit)
        self.assertTrue(self._wait_for(lambda: "Nmap done" in output_box.toPlainText()), output_box.toPlainText())
        output = output_box.toPlainText()
        self.assertIn(f"fake nmap args: -sV -p 3000; touch {marker} 10.0.0.9 -oA ", output)
        self.assertFalse(os.path.exists(marker))                 # the ';' never reached a shell

        self.assertTrue(self._wait_for(lambda: self._ports(ctrl, "10.0.0.9") == ["3000"]),
                        self._ports(ctrl, "10.0.0.9"))
        self.assertEqual([], self._ports(ctrl, "10.0.0.5"))      # only the selected host was scanned
        self.assertTrue(view.ui.NmapCommandStatusLabel.text().startswith("Queued: nmap -sV -p "))
        self.assertEqual(f"-sV -p 3000; touch {marker}", view.ui.NmapCommandInput.itemData(0))   # history

    def test_run_button_and_tab_survive_switching_hosts(self):
        ctrl, view = self._build()
        self._select(view, "10.0.0.5")
        view.ui.NmapCommandInput.setEditText("-F")
        view.ui.NmapCommandRunButton.click()
        output_box = view.ui.ServicesTabWidget.currentWidget().findChild(QtWidgets.QPlainTextEdit)
        self.assertTrue(self._wait_for(lambda: "Nmap done" in output_box.toPlainText()))
        self.assertTrue(self._wait_for(lambda: self._ports(ctrl, "10.0.0.5") == ["3000"]))    # import finished

        self._select(view, "10.0.0.9")
        self.assertNotIn("custom scan", self._tab_titles(view))
        self._select(view, "10.0.0.5")
        self.assertIn("custom scan", self._tab_titles(view))

    def test_bad_input_starts_nothing_and_says_why(self):
        ctrl, view = self._build()
        self._select(view, "10.0.0.5")
        view.ui.NmapCommandInput.setEditText('--script "http-title')
        view.ui.NmapCommandRunButton.click()
        self._qt_app.processEvents()

        self.assertNotIn("custom scan", self._tab_titles(view))
        self.assertIn("Could not read the options", view.ui.NmapCommandStatusLabel.text())
        self.assertEqual([], list(ctrl.processes))

    def test_picking_a_preset_fills_in_only_its_options(self):
        from app.nmap_command import PRESETS

        _ctrl, view = self._build()
        box = view.ui.NmapCommandInput
        self.assertEqual(len(PRESETS), box.count())
        box.setCurrentIndex(1)
        box.activated.emit(1)
        self.assertEqual(PRESETS[1][1], box.currentText())


if __name__ == "__main__":
    unittest.main()
