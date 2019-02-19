import os
import glob
import xml.etree.ElementTree as ET

class cci_data(object):

    def __init__(self):
        self.folder_location = os.getcwd()

    def get_cci_data(self, **kwargs):
        cci_file_location = kwargs.get('cci_file_location','')
        database_obj = kwargs.get('database_obj','')

        xmlns = "http://iase.disa.mil/cci"

        try:
            xml = ET.parse(cci_file_location)
        except Exception:
            print ("Error, unable to parse XML document.  Are you sure that's XCCDF?")

        try:
            total_vuln_dict = {}
            count = 0 
            tree = ET.ElementTree(file=cci_file_location)
            asset_list = []
            
        except Exception:
            total_vuln_list = []
            print ("Error processing data.")

        tree = ET.ElementTree(file=cci_file_location)

        root = tree.getroot()

        #database_obj.send_sql(sql_statement = 'DELETE FROM tblcci', sql_data=[])

        #sql = '''
        #        INSERT INTO tblcci (cci_item, control_item) VALUES (?,?)
        #      '''
        cci_list = []
        
        for child_of_root in root:
            if 'cci_items' in child_of_root.tag:
                for child2_of_child in child_of_root:
                    cci_id = child2_of_child.attrib['id']
                    for chid3_of_child2 in child2_of_child:
                        if 'references' in chid3_of_child2.tag:
                            for child4_of_child3 in chid3_of_child2:
                                if child4_of_child3.attrib['version'] == '4':
                                    control_id = child4_of_child3.attrib['index']
                                    cci_list.append((cci_id, control_id))

        #database_obj.send_sql(sql_statement = sql, sql_data=cci_list)
        


if __name__ == '__main__':

    c = cci_data()
    c.get_cci_data(cci_file_location = 'CCI/U_CCI_List.xml')

    
