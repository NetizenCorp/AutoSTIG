#Standard Library Import
import sqlite3 as sqlite

####################################################################

class Database(object):

    
    class Sqlite(object):

        def __init__(self):
            self.sqlite_db = None
            self.sqlite_key = None
            self.sqlite_cursor = None
            self.sqlite_query = None
            self.sqlite_results = None
            self.sqlite_rowcount = None
            self.sqlite_params = None
            self.database_encrypted = False
                    
        def sqlite_connect(self, dbname = None):
            if dbname is None:
                raise Exception('No database has been selected!')

            if self.sqlite_key is None and self.database_encrypted:
                raise Exception('No key present!')

            self.sqlite_db = sqlite.connect(dbname)
            self.sqlite_db.row_factory = self.dict_factory
            self.sqlite_cursor = self.sqlite_db.cursor()
            if self.database_encrypted:
                self.run_sqlite_query('pragma key={0}'.format(self.sqlite_key))
                #self.run_sqlite_query("PRAGMA key='password'", [])
                self.sqlite_db.commit()
            return self
            
        def dict_factory(self, cursor, row):
            d = {}
            for idx, col in enumerate(cursor.description):
                d[col[0]] = row[idx]
            return d
                    
        def run_sqlite_query(self, query = None, params = []):

            if query is None:
                raise Exception("Query cannot be blank")
            
            self.sqlite_query = query
            self.sqlite_params = params
            
            try:
                if self.database_encrypted:
                    self.sqlite_cursor.execute('pragma key={0}'.format(self.sqlite_key))
                self.sqlite_cursor.execute(self.sqlite_query, self.sqlite_params)
            except Exception as sqlite_error:
                self.sqlite_db.rollback()
                raise Exception("Database Error: {0}".format(sqlite_error))
            except Exception as sqlite_error:
                raise Exception("Database Error: {0}".format(sqlite_error))
            return self

        def sqlite_commit(self):
            try:
                self.sqlite_db.commit()
            except sqlite.Error as sqlite_error:
                raise Exception("Database Error: {0}".format(sqlite_error))
            except Exception as sqlite_error:
                raise Exception("Database Error: {0}".format(sqlite_error))
            finally:
                return self

        def sqlite_rollback(self):
            try:
                self.sqlite_db.rollback()
            except sqlite.Error as sqlite_error:
                raise Exception("Database Error: {0}".format(sqlite_error))
            except Exception as sqlite_error:
                raise Exception("Database Error: {0}".format(sqlite_error))
            finally:
                return self
            
        def get_sqlite_results(self):
            try:
                self.sqlite_results = self.sqlite_cursor.fetchall()
            except sqlite.Error as sqlite_error:
                raise Exception("Database Error: {0}".format(sqlite_error))
            except Exception as sqlite_error:
                raise Exception("Database Error: {0}".format(sqlite_error))
            finally:
                return self.sqlite_results
            
        def get_sqlite_count(self):
            try:
                self.sqlite_rowcount = self.sqlite_cursor.rowcount
            except sqlite.Error as sqlite_error:
                raise Exception("Database Error: {0}".format(sqlite_error))
            except Exception as sqlite_error:
                raise Exception("Database Error: {0}".format(sqlite_error))
            finally:
                return self.sqlite_rowcount

        def get_sqlite_insert_id(self):
            try:
                return self.sqlite_cursor.lastrowid
            except sqlite.Error as sqlite_error:
                raise Exception("Database Error: {0}".format(sqlite_error))
            except Exception as sqlite_error:
                raise Exception("Database Error: {0}".format(sqlite_error))
            
        def sqlite_close(self):
            try:
                self.sqlite_db.close()
            except sqlite.Error as sqlite_error:
                raise Exception("Database Error: {0}".format(sqlite_error))
            except Exception as sqlite_error:
                raise Exception("Database Error: {0}".format(sqlite_error))

        def sqlite_is_connected(self):
            if self.sqlite_db is None:
                return False
            
            return True
