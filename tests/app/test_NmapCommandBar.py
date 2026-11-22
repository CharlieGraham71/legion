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
        importer = getattr(ctrl, "nmapImporter", None)
        if importer is not None:    # let a result import finish before the project's database goes away
            self._wait_for(lambda: not importer.isRunning() and not getattr(ctrl, "_pendingNmapImports", None))
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

    def _hosts(self, view):
        return [view.HostsTableModel.getHostIPForRow(row) for row in range(view.HostsTableModel.rowCount(""))]

    def _output_box(self, view):
        page = view.ui.NmapOutputStack.currentWidget()
        if isinstance(page, QtWidgets.QPlainTextEdit):
            return page
        return page.findChild(QtWidgets.QPlainTextEdit)

    def _bottom_tab(self, view):
        return view.ui.BottomTabWidget.tabText(view.ui.BottomTabWidget.currentIndex())

    def _count_scheduler_runs(self, ctrl):
        calls = []
        scheduler = patch.object(ctrl, "scheduler", side_effect=lambda *args: calls.append(args))
        scheduler.start()
        self.addCleanup(scheduler.stop)
        # The importer's signal was connected to the bound method when the controller was built; reconnect it to
        # the patched one so the calls are counted.
        ctrl.nmapImporter.schedule.disconnect()
        ctrl.nmapImporter.schedule.connect(ctrl.scheduler)
        return calls

    def _type(self, view, text):
        view.ui.NmapCommandInput.setEditText(text)
        self._qt_app.processEvents()

    def test_with_no_host_and_no_typed_target_nothing_can_run(self):
        ctrl, view = self._build(hosts=())
        self.assertEqual("no target", view.ui.NmapCommandTargetLabel.text())
        self.assertFalse(view.ui.NmapCommandRunButton.isEnabled())

        self._type(view, "-sV")
        self.assertFalse(view.ui.NmapCommandRunButton.isEnabled())
        started, message = ctrl.runNmapCommand(view.nmapCommandBarTarget(), "-sV")

        self.assertFalse(started)
        self.assertIn("Type a target", message)
        self.assertEqual(1, view.ui.NmapOutputStack.count())     # only the placeholder
        self.assertEqual([], list(ctrl.processes))

    def test_a_typed_command_runs_as_typed_in_an_empty_project_and_starts_nothing_else(self):
        ctrl, view = self._build(hosts=())
        scheduler_runs = self._count_scheduler_runs(ctrl)
        marker = os.path.join(self.tmp, "marker")

        self._type(view, f"nmap -sV -p 3000; touch {marker} 10.0.0.9")
        self.assertIn("as typed", view.ui.NmapCommandTargetLabel.text())
        self.assertTrue(view.ui.NmapCommandRunButton.isEnabled())
        view.ui.NmapCommandInput.lineEdit().returnPressed.emit()

        self.assertEqual("Nmap", self._bottom_tab(view))
        output_box = self._output_box(view)
        self.assertTrue(self._wait_for(lambda: "Nmap done" in output_box.toPlainText()), output_box.toPlainText())
        # exactly the typed arguments, plus the -oA Legion needs to read the result back
        self.assertIn(f"fake nmap args: -sV -p 3000; touch {marker} 10.0.0.9 -oA ", output_box.toPlainText())
        self.assertFalse(os.path.exists(marker))                 # the ';' never reached a shell
        self.assertTrue(view.ui.NmapOutputTitleLabel.text().startswith("nmap -sV -p "))
        self.assertTrue(view.ui.NmapCommandStatusLabel.text().startswith("Queued: nmap -sV -p "))

        # the result is recorded: the host appears with its port ...
        self.assertTrue(self._wait_for(lambda: self._ports(ctrl, "10.0.0.9") == ["3000"]),
                        self._ports(ctrl, "10.0.0.9"))
        self.assertTrue(self._wait_for(lambda: "10.0.0.9" in self._hosts(view)), self._hosts(view))
        # ... but no follow-up tool was started for it, and no tool tab was added to the host
        self.assertTrue(self._wait_for(lambda: not ctrl.nmapImporter.isRunning()))
        self._wait_for(lambda: False, timeout=0.3)
        self.assertEqual([], scheduler_runs)
        self.assertEqual([], list(ctrl.processes))
        self.assertEqual(5, len(self._tab_titles(view)))
        self.assertEqual(f"nmap -sV -p 3000; touch {marker} 10.0.0.9", view.ui.NmapCommandInput.itemData(0))

    def test_without_a_typed_target_the_selected_host_is_scanned(self):
        ctrl, view = self._build()
        scheduler_runs = self._count_scheduler_runs(ctrl)
        self._select(view, "10.0.0.9")
        self._type(view, "-F")
        self.assertIn("10.0.0.9", view.ui.NmapCommandTargetLabel.text())

        view.ui.NmapCommandRunButton.click()

        output_box = self._output_box(view)
        self.assertTrue(self._wait_for(lambda: "Nmap done" in output_box.toPlainText()), output_box.toPlainText())
        self.assertIn("fake nmap args: -F 10.0.0.9 -oA ", output_box.toPlainText())
        self.assertTrue(self._wait_for(lambda: self._ports(ctrl, "10.0.0.9") == ["3000"]))
        self.assertEqual([], self._ports(ctrl, "10.0.0.5"))      # only the selected host was scanned
        self.assertTrue(self._wait_for(lambda: not ctrl.nmapImporter.isRunning()))
        self._wait_for(lambda: False, timeout=0.3)
        self.assertEqual([], scheduler_runs)

    def test_a_typed_target_wins_over_the_selected_host(self):
        ctrl, view = self._build()
        self._select(view, "10.0.0.5")
        self._type(view, "-F 10.0.0.9")
        self.assertIn("as typed", view.ui.NmapCommandTargetLabel.text())

        view.ui.NmapCommandRunButton.click()

        output_box = self._output_box(view)
        self.assertTrue(self._wait_for(lambda: "Nmap done" in output_box.toPlainText()))
        self.assertIn("fake nmap args: -F 10.0.0.9 -oA ", output_box.toPlainText())
        self.assertTrue(self._wait_for(lambda: self._ports(ctrl, "10.0.0.9") == ["3000"]))
        self.assertEqual([], self._ports(ctrl, "10.0.0.5"))

    def test_label_follows_the_selected_host_and_the_typed_text(self):
        _ctrl, view = self._build()
        self._select(view, "10.0.0.9")
        self.assertEqual("10.0.0.9", view.nmapCommandBarTarget())
        self.assertIn("10.0.0.9", view.ui.NmapCommandTargetLabel.text())
        self._select(view, "10.0.0.5")
        self.assertIn("10.0.0.5", view.ui.NmapCommandTargetLabel.text())

        self._type(view, "-sV 192.168.1.10")
        self.assertIn("as typed", view.ui.NmapCommandTargetLabel.text())
        self._type(view, "-sV")
        self.assertIn("10.0.0.5", view.ui.NmapCommandTargetLabel.text())

    def test_each_run_gets_its_own_output_and_the_output_survives_switching_hosts(self):
        ctrl, view = self._build()
        self._select(view, "10.0.0.5")
        self._type(view, "-F")
        view.ui.NmapCommandRunButton.click()
        first = self._output_box(view)
        self.assertTrue(self._wait_for(lambda: "Nmap done" in first.toPlainText()))
        self.assertTrue(self._wait_for(lambda: self._ports(ctrl, "10.0.0.5") == ["3000"]))

        self._select(view, "10.0.0.9")
        self.assertIs(first, self._output_box(view))             # still there after picking another host
        self.assertIn("-F 10.0.0.5", first.toPlainText())

        self._type(view, "-sV")
        view.ui.NmapCommandRunButton.click()
        second = self._output_box(view)
        self.assertIsNot(first, second)
        self.assertTrue(self._wait_for(lambda: "Nmap done" in second.toPlainText()))
        self.assertIn("-sV 10.0.0.9", second.toPlainText())
        self.assertIn("-F 10.0.0.5", first.toPlainText())        # the earlier output was not overwritten
        self.assertTrue(self._wait_for(lambda: self._ports(ctrl, "10.0.0.9") == ["3000"]))
        self.assertEqual("nmap -sV 10.0.0.9", view.ui.NmapOutputTitleLabel.text())

    def test_other_nmap_runs_still_start_the_scheduler(self):
        # Only the command bar is nmap-only; a host action such as a rescan keeps Legion's normal behaviour.
        ctrl, view = self._build()
        scheduler_runs = self._count_scheduler_runs(ctrl)
        outputfile = os.path.join(ctrl.logic.activeProject.properties.runningFolder, "plain-nmap-10.0.0.9")
        textbox = view.createNewTabForHost("10.0.0.9", "nmap (test)", True)

        ctrl.runCommand("nmap", "nmap (test)", "10.0.0.9", "", "", f"nmap -F 10.0.0.9 -oA {outputfile}",
                        "now", outputfile, textbox)

        self.assertTrue(self._wait_for(lambda: len(scheduler_runs) == 1), scheduler_runs)

    def test_bad_input_starts_nothing_and_says_why(self):
        ctrl, view = self._build()
        self._select(view, "10.0.0.5")
        self._type(view, '--script "http-title')
        view.ui.NmapCommandRunButton.click()
        self._qt_app.processEvents()

        self.assertEqual(1, view.ui.NmapOutputStack.count())
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

    def test_a_new_project_starts_with_an_empty_output_tab(self):
        ctrl, view = self._build()
        self._select(view, "10.0.0.5")
        self._type(view, "-F")
        view.ui.NmapCommandRunButton.click()
        box = self._output_box(view)
        self.assertTrue(self._wait_for(lambda: "Nmap done" in box.toPlainText()))
        self.assertTrue(self._wait_for(lambda: self._ports(ctrl, "10.0.0.5") == ["3000"]))
        self.assertEqual(2, view.ui.NmapOutputStack.count())

        view.start()

        self.assertEqual(1, view.ui.NmapOutputStack.count())
        self.assertEqual("", view.ui.NmapOutputTitleLabel.text())


if __name__ == "__main__":
    unittest.main()
