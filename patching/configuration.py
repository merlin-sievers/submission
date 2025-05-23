import configparser
from dataclasses import dataclass, field
from pathlib import Path
import sqlite3
import json
from typing import Any

from patched_lib_prepare.scan_entry import Result as PrepareResult

from helpers import CVEFunctionInfo

@dataclass
class Config:
    binary_path: str = ''
    patch_path: str = ''
    output_path: str = ''
    test_dir: str = ''
    version: str = ''
    product: str = ''
    firmware: str = ''
    test_binary: str = ''
    toolchain: str = ''
    cve: str = ''
    fn_info: CVEFunctionInfo = field(default_factory=lambda: CVEFunctionInfo('',''))
    search_for_original: bool = False

    def readMagmaConfig(self, path, section):
        try:
            # Read the configuration file
            config = configparser.ConfigParser()
            config.read(path)

            # Get values from the configuration file
            fn_name = config.get(section, "function.name")
            self.fn_info = CVEFunctionInfo(
                vuln_fn=fn_name,
                patch_fn=fn_name
            )
            self.binary_path = config.get(section, "binary.path")
            self.patch_path = config.get(section, "patch.path")
            self.output_path = config.get(section, "output.path")
        except configparser.Error as e:
            print("Error reading configuration:", e)

    @classmethod
    def fromPrepareResult(cls, prepResult: PrepareResult) -> list['Config']:
        cfgs: list[Config] = []
        for instance in prepResult.instances:

            cfg = Config(
                product=prepResult.product,
                version=prepResult.version,
                cve=prepResult.cve,
                toolchain=instance.toolchain,
                patch_path=instance.patched_path,
                binary_path=instance.affected_path,
                output_path=str(Path(instance.test_dir) / f'{prepResult.product}_{prepResult.cve}.so'),
                test_dir=instance.test_dir,
                firmware=str(Path(instance.affected_path).parent.absolute()),
            )
            cfgs.append(cfg)
        return cfgs

    @classmethod
    def fromJsonConfigFile(cls, json_path: str) -> list['Config']:
        with open(json_path, 'r') as f:
            data: list[Any] = json.load(f)  # pyright:ignore[reportAny, reportExplicitAny]
        return cls.fromJsonConfigs(data)

    @classmethod
    def readJsonConfig(cls, json_data: Any) -> 'Config':  # pyright:ignore[reportExplicitAny, reportAny]
        config = Config()
        config.binary_path = json_data["affected_path"]
        if "modified" in config.binary_path:
            raise ValueError
        if "patched" in config.binary_path:
            raise ValueError
        if "vuln_test" in config.binary_path:
            raise ValueError
        config.toolchain = json_data["toolchain"]
        config.patch_path = json_data["patched_path"]
        config.product = json_data["product"]
        config.output_path = json_data["test_dir"] + "/" + json_data["product"] + "_" + json_data["cve"] + ".so"
        config.test_dir = json_data["test_dir"]
        config.product = json_data["product"]
        config.version = json_data["version"]
        config.firmware = str(Path(config.binary_path).parent.absolute())
        return config

    @classmethod
    def fromJsonConfigs(cls, data: list[Any]) -> list['Config']:  # pyright:ignore[reportExplicitAny]

        results: list['Config'] = []

        for entry in data:  # pyright:ignore[reportAny]
            try:
                cfg = cls.readJsonConfig(entry)
                results.append(cfg)
            except ValueError:
                pass
            # version = entry.get("version")
            # patched_version = entry.get("patched_version")
            # patched_version = patched_version.get("version")
            # product = entry.get("product")
            # cve = entry.get("cve")
            # instances = entry.get("instances", [])
            #
            # for instance in instances:
            #     results.append({
            #         "product": product,
            #         "cve": cve,
            #         "affected_version": version,
            #         "patched_version": patched_version,
            #         "affected_path": instance.get("affected_path"),
            #         "patched_path": instance.get("patched_path"),
            #         "toolchain": instance.get("toolchain"),
            #         "test_dir": instance.get("test_dir")
            #     })

        return results




    def openBindiffResults(self):

        # Create a connection to the SQLite database
        print("Opening SQLite database:", self.sql_path)
        connection = sqlite3.connect(self.sql_path)

        try:
            # Create a cursor object to execute SQL queries
            cursor = connection.cursor()

            # Execute the SQL query
            query = """
            SELECT basicblock.address1, basicblock.address2, count(basicblockid)
            FROM basicblock
            JOIN instruction ON basicblockid = basicblock.id 
            GROUP BY basicblockid;
            """
            cursor.execute(query)

            # Fetch the results
            result_set = cursor.fetchall()

            # Process the results
            for row in result_set:
                address1, address2, count = row

            return result_set

        except sqlite3.Error as e:
            print("SQLite error:", e)

        finally:
            # Close the cursor and connection
            cursor.close()
            connection.close()


