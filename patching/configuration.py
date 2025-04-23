import configparser
import sqlite3
import json

class Config:

    def __init__(self):
        """
        This class contains all the configuration parameters for the patching process
        :param functionName:     String
        :param binary_path:      String
        """

        self.functionName = None
        self.binary_path = None
        self.patch_path = None
        self.output_path = None
        self.test_dir = None
        self.version = None
        self.product = None
        self.firmware = None

    def readMagmaConfig(self, path, section):
        try:
            # Read the configuration file
            config = configparser.ConfigParser()
            config.read(path)

            # Get values from the configuration file
            self.functionName = config.get(section, "function.name")
            print("Hallo", self.functionName)
            self.binary_path = config.get(section, "binary.path")
            self.patch_path = config.get(section, "patch.path")
            self.output_path = config.get(section, "output.path")
        except configparser.Error as e:
            print("Error reading configuration:", e)

    def readJsonConfig(self, json_path):
        with open(json_path, 'r') as f:
            data = json.load(f)

        results = []

        for entry in data:
            version = entry.get("version")
            patched_version = entry.get("patched_version")
            product = entry.get("product")
            cve = entry.get("cve")
            instances = entry.get("instances", [])

            for instance in instances:
                results.append({
                    "product": product,
                    "cve": cve,
                    "affected_version": version,
                    "patched_version": patched_version,
                    "affected_path": instance.get("affected_path"),
                    "patched_path": instance.get("patched_path"),
                    "toolchain": instance.get("toolchain"),
                    "test_dir": instance.get("test_dir")
                })

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


