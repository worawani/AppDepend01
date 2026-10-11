import csv
import tempfile
import unittest
from pathlib import Path

from appdepend import analysis
from appdepend.cli import main
from appdepend.config import Settings
from appdepend.inputs import VM, Flow, HostData, load_collected, load_inventory, load_known, load_waves
from appdepend.model import APP, ADMIN, INFRA, build_graph
from appdepend.netutil import CidrTable, classify_ip, split_ips
from appdepend.sample import generate


def host(name, ip, flows, samples=1000):
    h = HostData(hostname=name, ips={ip}, samples=samples, start="2026-09-01T00:00:00", end="2026-09-22T00:00:00")
    for direction, remote, port, proc, n, *states in flows:
        h.flows[(direction, remote, port, proc)] = Flow(direction, remote, port, proc, "", "",
                                                        set(states or ["Established"]), "", "", n, 1)
    return h


class NetUtilTests(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(classify_ip("10.1.2.3"), "private")
        self.assertEqual(classify_ip("100.70.0.1"), "private")
        self.assertEqual(classify_ip("8.8.8.8"), "public")
        self.assertEqual(classify_ip("127.0.0.1"), "loopback")
        self.assertEqual(classify_ip("::ffff:10.0.0.1"), "private")

    def test_split_ips_drops_link_local(self):
        self.assertEqual(split_ips("10.0.0.1, fe80::1%4;10.0.0.2 127.0.0.1"), ["10.0.0.1", "10.0.0.2"])

    def test_longest_prefix(self):
        t = CidrTable()
        t.add("10.0.0.0/8", "wide")
        t.add("10.1.0.0/16", "narrow")
        self.assertEqual(t.lookup("10.1.2.3"), "narrow")
        self.assertEqual(t.lookup("10.2.0.1"), "wide")
        self.assertIsNone(t.lookup("192.168.1.1"))


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.inv = {
            "web": VM("WEB", ips={"10.0.0.1"}),
            "db_vm": VM("DB_VM", ips={"10.0.0.2"}, dns_name="db01.corp.local"),
            "dc": VM("DC", ips={"10.0.0.9"}, role="shared"),
        }
        self.hosts = {
            "web": host("WEB", "10.0.0.1", [
                ("Outbound", "10.0.0.2", 1433, "w3wp", 900),
                ("Outbound", "10.0.0.9", 445, "w3wp", 10),      # to shared VM -> infra
                ("Outbound", "10.0.0.9", 53, "svchost", 500),   # infra port
                ("Outbound", "10.9.9.9", 1521, "w3wp", 5, "SynSent"),
                ("Inbound", "10.0.0.50", 3389, "svchost", 3),
            ]),
            # Windows hostname differs from the VM name; matched through the DNS name
            "db01": host("DB01", "10.0.0.2", [("Inbound", "10.0.0.1", 1433, "sqlservr", 950)]),
        }

    def build(self, waves=None, settings=None):
        return build_graph(self.inv, waves or {}, self.hosts, CidrTable(), settings or Settings())

    def test_both_sides_merge_into_one_edge(self):
        g = self.build()
        e = g.edges[("WEB", "DB_VM", 1433)]
        self.assertEqual(e.observed_by, {"client", "server"})
        self.assertEqual(e.client_processes, {"w3wp"})
        self.assertEqual(e.server_processes, {"sqlservr"})
        self.assertAlmostEqual(e.persistence, 0.95)
        self.assertEqual(e.category, APP)
        self.assertEqual(g.nodes["DB_VM"].host.hostname, "DB01")

    def test_categories(self):
        g = self.build()
        self.assertEqual(g.edges[("WEB", "DC", 445)].category, INFRA)
        self.assertEqual(g.edges[("WEB", "DC", 53)].category, INFRA)
        self.assertEqual(g.edges[("10.0.0.50", "WEB", 3389)].category, ADMIN)
        self.assertTrue(g.edges[("WEB", "10.9.9.9", 1521)].failed_only)

    def test_cross_wave_and_move_groups(self):
        waves = {"web": {"wave": "Wave 1"}, "db_vm": {"wave": "Wave 2"}}
        g = self.build(waves)
        xw = analysis.cross_wave(g)
        self.assertEqual(len(xw), 1)
        self.assertEqual((xw[0]["Client"], xw[0]["Server"], xw[0]["Risk"]), ("WEB", "DB_VM", "High"))
        groups = analysis.move_groups(g)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["Status"], "SPLIT ACROSS WAVES")
        self.assertNotIn("DC", groups[0]["Members"])  # shared VM never glues groups

    def test_failed_only_does_not_count_as_unknown_dependency(self):
        g = self.build({"web": {"wave": "W1"}, "db_vm": {"wave": "W1"}})
        cov = analysis.coverage(g)
        summary = analysis.wave_summary(g, cov, analysis.cross_wave(g), analysis.move_groups(g))
        self.assertEqual(summary[0]["Unknown Internal Endpoints"], 0)
        self.assertEqual(summary[0]["Status"], "GREEN")

    def test_group_min_persistence(self):
        s = Settings()
        s.group_min_persistence = 0.99
        g = self.build({"web": {"wave": "W1"}, "db_vm": {"wave": "W2"}}, s)
        self.assertEqual(analysis.move_groups(g), [])

    def test_check_selection(self):
        g = self.build({"web": {"wave": "Wave 2"}, "db_vm": {"wave": "Wave 1"}})
        res = analysis.check_selection(g, {"WEB"}, "Wave 2")
        app = [d for d in res["dependencies"] if d["Category"] == APP]
        verdicts = {d["Peer"]: d["Verdict"] for d in app}
        self.assertIn("already in OCI", verdicts["DB_VM"])
        self.assertIn("never established", verdicts["10.9.9.9"])
        self.assertEqual([c["VM"] for c in res["closure"]], ["DB_VM"])


class EndToEndTests(unittest.TestCase):
    def test_sample_dataset_finds_planted_problems(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            generate(root)
            inv = load_inventory([root / "inventory.csv"])
            s = Settings()
            s.shared_vms = {"file01"}
            s.group_min_persistence = 0.05
            g = build_graph(inv, load_waves(root / "waves.csv"), load_collected(root / "collected"),
                            load_known(root / "known-endpoints.csv"), s)
            groups = analysis.move_groups(g)
            split = [r for r in groups if r["Status"] != "OK"]
            self.assertEqual(len(split), 1)
            self.assertEqual(split[0]["VMs To Re-wave"], "HR-SQL01")
            self.assertEqual(split[0]["Suggested Wave"], "Wave 2")
            unknown = {r["Endpoint"]: r for r in analysis.unknown_endpoints(g)}
            self.assertTrue(unknown["10.50.1.20"]["Action"].startswith("IDENTIFY"))
            self.assertEqual(unknown["52.84.10.20"]["Type"], "Internet")
            cov = {r["VM"]: r for r in analysis.coverage(g)}
            self.assertEqual(cov["LEGACY01"]["Collected"], "no")
            self.assertIn("Short collection", cov["RPT01"]["Issues"])
            self.assertEqual(cov["erp-app02_vm"]["Collected"], "yes")

    def test_cli_writes_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            generate(root / "s")
            common = ["-d", str(root / "s/collected"), "-i", str(root / "s/inventory.csv"),
                      "-w", str(root / "s/waves.csv"), "-k", str(root / "s/known-endpoints.csv"), "-o", str(root / "out")]
            self.assertEqual(main(["analyze", *common]), 0)
            self.assertEqual(main(["check", *common, "--wave", "wave 2"]), 0)
            for f in ("dependency-report.xlsx", "dependency-report.html", "graph.json", "check-Wave_2.html", "check-Wave_2.xlsx"):
                self.assertTrue((root / "out" / f).stat().st_size > 0, f)

    def test_rvtools_xlsx_inventory(self):
        from openpyxl import Workbook

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "rvtools.xlsx"
            wb = Workbook()
            ws = wb.active
            ws.title = "vInfo"
            ws.append(["VM", "Powerstate", "Template", "DNS Name", "Primary IP Address", "OS according to the VMware Tools"])
            ws.append(["APP01", "poweredOn", "False", "app01.corp.local", "10.1.1.1", "Microsoft Windows Server 2016 (64-bit)"])
            ws.append(["TPL-2019", "poweredOff", "True", "", "", ""])
            net = wb.create_sheet("vNetwork")
            net.append(["VM", "IPv4 Address"])
            net.append(["APP01", "10.1.1.1, 10.2.2.2"])
            wb.save(p)
            inv = load_inventory([p])
            self.assertEqual(list(inv), ["app01"])
            self.assertEqual(inv["app01"].ips, {"10.1.1.1", "10.2.2.2"})
            self.assertTrue(inv["app01"].is_windows)

    def test_collector_csv_with_bom(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            with open(d / "SRV1_connections.csv", "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f, quoting=csv.QUOTE_ALL)
                w.writerow(["Hostname", "Direction", "RemoteAddress", "Port", "ProcessName", "ProcessPath", "ServiceNames",
                            "States", "FirstSeen", "LastSeen", "SampleCount", "MaxConcurrent"])
                w.writerow(["SRV1", "Outbound", "10.0.0.5", "1433", "app", "", "", "Established;TimeWait",
                            "2026-09-01T00:00:00", "2026-09-02T00:00:00", "12", "3"])
            hosts = load_collected(d)
            self.assertEqual(list(hosts), ["srv1"])
            fl = next(iter(hosts["srv1"].flows.values()))
            self.assertEqual((fl.port, fl.states, fl.samples), (1433, {"Established", "TimeWait"}, 12))


if __name__ == "__main__":
    unittest.main()
