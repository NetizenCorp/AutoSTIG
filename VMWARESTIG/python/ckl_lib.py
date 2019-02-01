import os
import glob
import xml.etree.ElementTree as ET
import openpyxl
from openpyxl.styles import Alignment
import time
import datetime
from operator import itemgetter
import copy

class Ckl_Data(object):

    def __init__(self):
        self.folder_location = os.getcwd()

    def get_ckl_data(self, **kwargs):
        ckl_list = kwargs.get("ckl_file_list", [])
                
        total_vuln_list = []

        for ckl in ckl_list:            
            xmlns = "http://checklists.nist.gov/xccdf/1.1"
            data = None
            file_data = {}
            base=os.path.basename(ckl)

            file_data['file_name'] = base
            file_data['file_data'] = []
                      
            try:
                xml = ET.parse(ckl)
            except Exception:
                print "Error, unable to parse XML document.  Are you sure that's XCCDF?"

            try:
                total_vuln_dict = {}
                count = 0 
                tree = ET.ElementTree(file=ckl)
                asset_list = []
                
            except Exception:
                total_vuln_list = []
                print "Error processing data."


            total_vuln_dict = {}
            count = 0 
            tree = ET.ElementTree(file=ckl)
            asset_list = []
            for elem in tree.iter("ASSET"):
                asset_data = {}
                for child in elem:
                    if child.tag  == "HOST_NAME":
                        asset_data["host_name"] = child.text
                    if child.tag  == "HOST_IP":
                        asset_data["host_ip"] = child.text
                    if child.tag  == "HOST_MAC":
                        asset_data["host_mac"] = child.text

                asset_list = asset_data
                
           
            sid_name = ''
            for elem in tree.iter("STIG_INFO"):
                for child in elem:
                    if "SI_DATA" in child.tag:                        
                        for child2 in child:                             
                            if child2.tag == "SID_NAME":
                                sid_name = child2.text
                            elif child2.tag == "SID_DATA":
                                if sid_name == "title":
                                    asset_data["title"] = child2.text

            
            total_vuln_dict["host_data"] = asset_list
            file_data['file_data'].append(total_vuln_dict)

            for elem in tree.iter("VULN"):
                total_vuln_dict = {}
                vuln_list = []
                for child in elem:
                    vuln_dict = {}
                    if "STIG_DATA" in child.tag:
                        for child2 in child:
                            if child2.tag == "VULN_ATTRIBUTE":
                                vuln_dict["vuln_attrib"] = child2.text
                            elif child2.tag == "ATTRIBUTE_DATA":
                                vuln_dict["attrib_data"] = child2.text
                        vuln_list.append(vuln_dict)
                    else:
                        vuln_dict[child.tag.lower()] = child.text
                        vuln_list.append(vuln_dict)

                count += 1
                status = "Not_Reviewed"
                for vuln in vuln_list:
                    if "status" in vuln:
                        status = vuln["status"].lower()
                        
                #if status == "open":                        
                total_vuln_dict["Vuln{0}".format(count)] = vuln_list
                file_data['file_data'].append(total_vuln_dict)

            total_vuln_list.append(file_data)
            
        return total_vuln_list

    def extract_ckl(self,  **kwargs):
        ckl_raw_data_list = kwargs.get("ckl_raw_data_list", [])
        cci_list = kwargs.get("cci_list", None)
        dodi_list = kwargs.get("dodi_list", None)
        #print cci_list
        ret_value = []

        for cc in ckl_raw_data_list:
            
            vuln_num = ''
            severity = ''
            ia_control = ''
            check_content = ''
            title = ''
            host_name = ''
            
            weakness = ''
            raw_cat = ''
            mit_cat = ''
            vuln_ident = ''
            vuln_description = ''
            rule_ver = ''
            rule_title = ''
            cci_ref = ''
            status = ''
            vuln_discuss = ''
            group_title = ''
            stig_ref = ''
            vuln_status = ''

            #ret_value2 = []
            #ret_value2 = copy.deepcopy(ret_value)
            file_name = cc['file_name']
            host_data = filter(lambda x: 'host_data' in x, cc['file_data'])
            title = host_data[0]['host_data']['title']
            host_name = host_data[0]['host_data']['host_name']

            for c in cc['file_data']:
                if not 'host_data' in c:
                    for key, value in c.iteritems():
                        stig_cci_list = []
                        ret_dict = {}
                        matcher = (d for d in value if d['vuln_attrib'] == 'Vuln_Num')
                        d = next(matcher, None)
                        vuln_num = d['attrib_data']
                        ret_dict['vuln_num'] = vuln_num
                        #print vuln_num

                        cci_ref = ""
                        cci_ia_control = ""
                        
                        for e in value:
                            try:
                                if e['vuln_attrib'] == 'CCI_REF':
                                    cci_ref = cci_ref + e['attrib_data'] + ', '
                                    test = filter(lambda x: x[0] == e['attrib_data'], cci_list)
                                    if len(test) > 0:
                                        if not test[0][1] in stig_cci_list:
                                            stig_cci_list.append(test[0][1])
                            except Exception:
                                pass

                        ret_dict['cci_ref'] = cci_ref[:-2]
                        
                        matcher = (d for d in value if d['vuln_attrib'] == 'Severity')
                        d = next(matcher, None)
                        severity = d['attrib_data']
                        ret_dict['severity'] = severity
                    
                        if severity.lower() == "high":
                            raw_cat = "CAT I"
                            mit_cat = "CAT II"
                        elif severity.lower() == "medium":
                            raw_cat = "CAT II"
                            mit_cat = "CAT III"
                        elif severity.lower() == "low":
                            raw_cat = "CAT III"
                            mit_cat = "CAT III"

                        ret_dict['raw_cat'] = raw_cat
                        ret_dict['mit_cat'] = mit_cat
                        
                        matcher = (d for d in value if d['vuln_attrib'] == 'IA_Controls')
                        d = next(matcher, None)
                        ia_control = d['attrib_data']
                        if ia_control != None:
                            test = filter(lambda x: x[0] == ia_control, dodi_list)
                            if len(test) > 0:
                                if not test[0][1] in stig_cci_list:
                                    stig_cci_list.append(test[0][1]) 
                            #print test
                            #ret_dict['ia_control'] = ia_control
                            
                        for stig_cci in stig_cci_list:
                            cci_ia_control +=  stig_cci + ","
                        #print cci_ia_control[:-1]  
                        ret_dict['ia_control'] = cci_ia_control[:-1]

                        matcher = (d for d in value if d['vuln_attrib'] == 'Check_Content')
                        d = next(matcher, None)
                        check_content = d['attrib_data']
                        ret_dict['check_content'] = check_content

                        matcher = (d for d in value if d['vuln_attrib'] == 'Fix_Text')
                        d = next(matcher, None)
                        fix_text = d['attrib_data']
                        ret_dict['fix_text'] = fix_text #.replace("'","''")
                        #print fix_text.replace("'","''")
                        #print 

                        matcher = (d for d in value if d['vuln_attrib'] == 'Rule_Ver')
                        d = next(matcher, None)
                        rule_ver = d['attrib_data']
                        ret_dict['rule_ver'] = rule_ver

                        matcher = (d for d in value if d['vuln_attrib'] == 'Rule_Title')
                        d = next(matcher, None)
                        rule_title = d['attrib_data']
                        ret_dict['rule_title'] = rule_title

                        matcher = (d for d in value if d['vuln_attrib'] == 'Vuln_Discuss')
                        d = next(matcher, None)
                        vuln_discuss = d['attrib_data']
                        ret_dict['vuln_discuss'] = vuln_discuss #.replace("'","''")
                        #print vuln_discuss.replace("'","''")

                        matcher = (d for d in value if d['vuln_attrib'] == 'Group_Title')
                        d = next(matcher, None)
                        group_title = d['attrib_data']
                        ret_dict['group_title'] = group_title

                        matcher = (d for d in value if d['vuln_attrib'] == 'STIGRef')
                        d = next(matcher, None)
                        stig_ref = d['attrib_data']
                        ret_dict['stig_ref'] = stig_ref

                        matcher = (d for d in value if 'status' in d)
                        d = next(matcher, None)
                        status = d['status']
                        ret_dict['vuln_status'] = status
                        ret_dict['status'] = 'Ongoing'

                        ret_dict['host_name'] = host_name
                        ret_dict['title'] = title
                        ret_dict['file_name'] = file_name

                        #print ret_dict
                        #print
                        #print '#####################################'
                        #print
                        
                        ret_value.append(ret_dict)
                        ret_dict = {}
                        
            #ret_value = ret_value2

        return ret_value

    def ckl_in_database(self, **kwargs):
        file_list = kwargs.get('file_list', [])

        self.clk_data_ret = Ckl_Data().get_ckl_data(ckl_file_list = file_list)
        self.ret_value = Ckl_Data().extract_ckl(ckl_raw_data_list = self.clk_data_ret)

        db_list = []
        
        for r in self.ret_value:
            new_list = []
            new_list = copy.deepcopy(db_list)
            #print r['ia_control']
            t = (r['host_name'], r['vuln_num'], r['vuln_status'], r['rule_ver'], r['rule_title'],
                            r['severity'], r['cci_ref'], r['ia_control'], r['check_content'],
                            r['status'], r['raw_cat'], r['mit_cat'], r['fix_text'], r['stig_ref'],
                            r['vuln_discuss'], r['group_title'], r['host_name'], r['vuln_num'], r['ia_control'], 
                            r['file_name'])
            new_list.append(t)
            db_list = new_list
            
        return db_list


if __name__ == '__main__':

    #clk_data_ret = Ckl_Data().get_ckl_data(ckl_file_list = ['C:\Users\jonathan.berns.GRSI\Desktop\stig zip file\Test Win 10.ckl'])

    clk_data_ret = Ckl_Data().get_ckl_data(ckl_file_list = ['C:\Users\jonathan.berns.GRSI\Desktop\stig zip file\win7.ckl'])
    '''
                                                            ,
                                            'C:\Users\jonathan.berns.GRSI\Desktop\stig zip file\win8.ckl',
                                            'C:\Users\jonathan.berns.GRSI\Desktop\stig zip file\win10.ckl',
                                            'C:\Users\jonathan.berns.GRSI\Desktop\stig zip file\win2012dc.ckl',
                                            'C:\Users\jonathan.berns.GRSI\Desktop\stig zip file\win2012ms.ckl'])
    '''

    ret_value = Ckl_Data().extract_ckl(ckl_raw_data_list = clk_data_ret)

    for r in ret_value:
       print r['cci_ref']





        
        
