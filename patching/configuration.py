import configparser
import sqlite3


class Config:

    def __int__(self):
        """
        This class contains all the configuration parameters for the patching process
        :param functionName:     String
        :param sql_path:         String
        """
        config = configparser.ConfigParser()

        try:
            # Read the configuration file
            config.read("config.properties")

            # Get values from the configuration file
            self.functionName = config.get("DEFAULT", "function.name")
            self.sql_path = config.get("DEFAULT", "SQL.path")

        except configparser.Error as e:
            print("Error reading configuration:", e)

    def openBindiffResults(self):

        # Create a connection to the SQLite database
        connection = sqlite3.connect(self.sql_path)

        try:
            # Create a cursor object to execute SQL queries
            cursor = connection.cursor()

            # Execute the SQL query
            query = """""
            SELECT basicblock.address1, basicblock.address2, count(basicblockid)
            FROM basicblock
            JOIN instruction ON basicblockid = basicblock.id
            WHERE functionid = ?  
            GROUP BY basicblockid;
            """""

            # Replace 'your_function_id' with the actual function ID you want to query
            function_id = "your_function_id"
            cursor.execute(query, (function_id,))

            # Fetch the results
            result_set = cursor.fetchall()

            # Process the results
            for row in result_set:
                address1, address2, count = row
                print(f"Address1: {address1}, Address2: {address2}, Count: {count}")

        except sqlite3.Error as e:
            print("SQLite error:", e)

        finally:
            # Close the cursor and connection
            cursor.close()
            connection.close()
