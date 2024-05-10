import configparser
import sqlite3


class Config:

    def __init__(self, path, section):
        """
        This class contains all the configuration parameters for the patching process
        :param functionName:     String
        :param sql_path:         String
        :param binary_path:      String
        """
        config = configparser.ConfigParser()
        self.functionName = None
        self.sql_path = None
        self.binary_path = None
        self.patch_path = None
        try:
            # Read the configuration file
            config.read(path)

            # Get values from the configuration file
            self.functionName = config.get(section, "function.name")
            print("Hallo", self.functionName)
            self.sql_path = config.get(section, "SQL.path")
            self.binary_path = config.get(section, "binary.path")
            self.patch_path = config.get(section, "patch.path")
            self.output_path = config.get(section, "output.path")
        except configparser.Error as e:
            print("Error reading configuration:", e)

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
