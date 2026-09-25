import ipaddress
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import URLError

import maxminddb
import update as app


def source(name="test", fmt="netset", allow_empty=False):
    return {"name": name, "url": "https://example.test/feed", "format": fmt,
            "category": "aggregated_blocklist", "refresh_seconds": 900,
            "max_age_seconds": 1800, "enabled": True, "allow_empty": allow_empty}


class ReputationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = {"output": self.root / "test.mmdb", "cache_directory": self.root / "cache",
                       "timeout_seconds": 5, "max_download_bytes": 1024, "sources": [source()]}

    def seed(self, body=b"8.8.8.8\n", now=1000, feed=None):
        with patch.object(app, "download", return_value=(body, {"etag": "version1"})):
            return app.get_source(feed or source(), self.config, now)

    def test_normalization_comments_and_duplicate_networks(self):
        rows = app.parse_feed(b"# comment\n8.8.8.8 # note\n1.1.1.9/24\n1.1.1.0/24\n2001:db8::1\n", source())
        self.assertEqual({str(n) for n, _ in rows}, {"8.8.8.8/32", "1.1.1.0/24", "2001:db8::1/128"})

    def test_invalid_html_empty_and_catchall(self):
        for body in (b"<html>error</html>", b"", b"0.0.0.0/0", b"::/0", b"::/96"):
            with self.assertRaises(app.UpdateError):
                app.parse_feed(body, source())
        self.assertEqual(app.parse_feed(b"[]", source(fmt="feodo_json", allow_empty=True)), [])

    def test_feodo_preserves_endpoint_and_observation_dates(self):
        record = {"ip_address": "8.8.8.8", "port": 443, "status": "online", "malware": "Test",
                  "first_seen": "2020-01-01", "last_online": "2020-02-01"}
        rows = app.parse_feed(json.dumps([record, record]).encode(), source(fmt="feodo_json"))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1]["port"], 443)
        self.assertEqual(rows[0][1]["reported_last_online"], "2020-02-01")
        record["port"] = 65536
        with self.assertRaises(app.UpdateError):
            app.parse_feed(json.dumps([record]).encode(), source(fmt="feodo_json"))

    def test_overlap_and_ipv6_round_trip(self):
        a, b, c = {"source": "range"}, {"source": "host", "port": 443}, {"source": "ipv6"}
        entries = [(app.network("8.8.8.0/24"), a), (app.network("8.8.8.8"), b),
                   (app.network("2001:db8::/120"), c)]
        manifest = app.publish(self.config["output"], entries, {"database_version": "test", "sources": []})
        with maxminddb.open_database(str(self.config["output"])) as reader:
            self.assertEqual(reader.get("8.8.8.7")["matches"], [a])
            self.assertEqual({x["source"] for x in reader.get("8.8.8.8")["matches"]}, {"host", "range"})
            self.assertEqual(reader.get("8.8.8.9")["matches"], [a])
            self.assertEqual(reader.get("2001:db8::1")["matches"], [c])
            self.assertIsNone(reader.get("1.1.1.1"))
            self.assertIsNone(reader.get("2001:db9::1"))
        self.assertEqual(manifest["sha256"], app.digest(self.config["output"].read_bytes()))

    def test_nested_and_duplicate_evidence_is_not_lost(self):
        a, b = {"source": "a"}, {"source": "b"}
        rows = list(app.merge_networks([(app.network("8.8.8.0/24"), a), (app.network("8.8.8.0/25"), a),
                                      (app.network("8.8.8.64/26"), b)]))
        for address, expected in [("8.8.8.1", {"a"}), ("8.8.8.70", {"a", "b"}), ("8.8.8.200", {"a"})]:
            values = [matches for net, matches in rows if ipaddress.ip_address(address) in net]
            self.assertEqual(len(values), 1)
            self.assertEqual({v["source"] for v in values[0]}, expected)

    def test_refresh_interval_and_304_confirmation(self):
        self.seed()
        with patch.object(app, "download") as download:
            _, status = app.get_source(source(), self.config, 1100)
            download.assert_not_called()
            self.assertEqual(status["status"], "cached")
        with patch.object(app, "download", return_value=(None, {})):
            _, status = app.get_source(source(), self.config, 2000)
            self.assertEqual(status["status"], "not_modified")
            self.assertEqual(status["last_confirmed_at"], app.utc(2000))
            self.assertEqual(status["content_changed_at"], app.utc(1000))

    def test_failed_download_uses_cache_then_expires(self):
        self.seed()
        with patch.object(app, "download", side_effect=URLError("offline")):
            rows, status = app.get_source(source(), self.config, 2000)
            self.assertEqual(status["status"], "stale")
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0][1]["expires_at"], app.utc(2800))
            rows, status = app.get_source(source(), self.config, 3000)
            self.assertEqual(status["status"], "expired")
            self.assertEqual(rows, [])

    def test_first_download_failure_does_not_publish(self):
        with patch.object(app, "download", side_effect=URLError("offline")):
            with self.assertRaises(app.UpdateError):
                app.update(self.config)
        self.assertFalse(self.config["output"].exists())

    def test_malformed_download_preserves_snapshot(self):
        self.seed()
        with patch.object(app, "download", return_value=(b"<html>failed</html>", {})):
            rows, status = app.get_source(source(), self.config, 2000)
        self.assertEqual(status["status"], "stale")
        self.assertEqual(str(rows[0][0]), "8.8.8.8/32")
        self.assertEqual((self.root / "cache/test/snapshot.txt").read_bytes(), b"8.8.8.8\n")

    def test_membership_removal_and_previous_database(self):
        with patch.object(app, "download", return_value=(b"8.8.8.8\n", {})):
            app.update(self.config)
        previous = self.config["output"].read_bytes()
        with patch.object(app, "download", return_value=(b"1.1.1.1\n", {})):
            app.update(self.config, force=True)
        with maxminddb.open_database(str(self.config["output"])) as reader:
            self.assertIsNone(reader.get("8.8.8.8"))
            self.assertIsNotNone(reader.get("1.1.1.1"))
        self.assertEqual(self.root.joinpath("test.mmdb.previous").read_bytes(), previous)

    def test_empty_mmdb_is_valid(self):
        app.publish(self.config["output"], [], {"database_version": "empty", "sources": []})
        with maxminddb.open_database(str(self.config["output"])) as reader:
            self.assertIsNone(reader.get("8.8.8.8"))

    def test_lock_excludes_second_updater(self):
        path = self.root / "build.lock"
        with app.lock(path):
            with self.assertRaises(app.UpdateError):
                with app.lock(path):
                    self.fail("second lock acquired")

    def test_large_change_requires_explicit_acceptance(self):
        body = "\n".join(f"8.8.8.{i}" for i in range(128)).encode()
        self.seed(body)
        with patch.object(app, "download", return_value=(b"1.1.1.1\n", {})):
            rows, status = app.get_source(source(), self.config, 2000)
            self.assertEqual(len(rows), 128)
            self.assertEqual(status["status"], "stale")
            rows, status = app.get_source(source(), self.config, 2000, accept_large_change=True)
            self.assertEqual(len(rows), 1)
            self.assertEqual(status["status"], "fresh")

    def test_writer_failure_preserves_published_database(self):
        entries = [(app.network("8.8.8.8"), {"source": "test"})]
        app.publish(self.config["output"], entries, {"database_version": "old"})
        old = self.config["output"].read_bytes()
        with patch.object(app.MMDBWriter, "to_db_file", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                app.publish(self.config["output"], entries, {"database_version": "new"})
        self.assertEqual(self.config["output"].read_bytes(), old)

    def test_all_expired_does_not_replace_previous_database(self):
        with patch.object(app.time, "time", return_value=1000), patch.object(app, "download", return_value=(b"8.8.8.8\n", {})):
            app.update(self.config)
        old = self.config["output"].read_bytes()
        with patch.object(app.time, "time", return_value=3000), patch.object(app, "download", side_effect=URLError("offline")):
            with self.assertRaises(app.UpdateError):
                app.update(self.config)
        self.assertEqual(self.config["output"].read_bytes(), old)

    def test_config_relative_paths_and_validation(self):
        path = self.root / "config.json"
        config = {"output": "data/test.mmdb", "cache_directory": "cache", "sources": [source()]}
        path.write_text(json.dumps(config))
        self.assertEqual(app.load_config(path)["output"], self.root / "data/test.mmdb")
        config["sources"][0]["url"] = "http://example.test/feed"
        path.write_text(json.dumps(config))
        with self.assertRaises(app.UpdateError):
            app.load_config(path)


if __name__ == "__main__":
    unittest.main()
