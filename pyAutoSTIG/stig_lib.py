import ast
import os
import shutil
import zipfile

import xml.etree.ElementTree as ET

try:
    from xml.etree import cElementTree as etree
except ImportError:
    from xml.etree import ElementTree as etree


class stig_data(object):

    def run_stig(self, sqlite_db, application_path):
        stig_list = []

        for filename in os.listdir("STIGs/"):
            if '.zip' in filename:
                #stig_list.append(self.get_stig_data(filename))
                stig = self.get_stig_data(filename)
                stig_filename = '{0}'.format(filename.split('.')[0]) 

                if not os.path.isfile(application_path + "/" + stig_filename + ".scl"):
                    sqlite_db.sqlite_key = 'password'
                    sqlite_db.database_encrypted = True
                    sqlite_db.sqlite_connect(application_path + "/" + stig_filename + ".scl")
                    sqlite_db.run_sqlite_query('''create table app (version float)''', [])
                    sqlite_db.run_sqlite_query('''CREATE TABLE 'STIG' (
                                                'stig_id' TEXT,
                                                'stig_title' TEXT,
                                                'stig_status' TEXT,
                                                'stig_description' TEXT,
                                                'stig_release' TEXT, 
                                                'stig_version' TEXT
                                                );''', [])
                    sqlite_db.run_sqlite_query('''CREATE TABLE 'profiles' (
                                                    'profile_id' TEXT,
                                                    'profile_title' TEXT,
                                                    'profile_description' TEXT
                                                );''', [])
                    sqlite_db.run_sqlite_query('''CREATE TABLE 'profile_vulns' (
                                                    'profile_id' TEXT,
                                                    'vuln_id' TEXT
                                                );''', [])
                    sqlite_db.run_sqlite_query('''CREATE TABLE 'vulns' (
                                                    'vuln_id' TEXT,
                                                    'vuln_title' TEXT,
                                                    'vuln_description' TEXT,
                                                    'vuln_rule_id' TEXT,
                                                    'vuln_rule_severity' TEXT,
                                                    'vuln_rule_weight' TEXT,
                                                    'vuln_rule_version' TEXT,
                                                    'vuln_rule_title' TEXT,
                                                    'vuln_rule_description' TEXT,
                                                    'vuln_rule_fix_text' TEXT,
                                                    'vuln_rule_check' TEXT
                                                );''', [])
                    sqlite_db.run_sqlite_query('''CREATE TABLE 'vuln_cci' (
                                                    'vuln_id' TEXT,
                                                    'cci_id' TEXT
                                                );''', [])
                    sqlite_db.run_sqlite_query('''insert into app values (1.0)''', [])
                    sqlite_db.sqlite_commit()
                
                    sqlite_db.run_sqlite_query('''INSERT INTO STIG (stig_id, stig_title, stig_status, stig_description, stig_release, stig_version) 
                                                VALUES (?, ?, ?, ?, ?, ?)''', [stig['stig_id'], stig['stig_title'],stig['stig_status'],
                                                                            stig['stig_description'], stig['stig_release'], stig['stig_version']])

                    for profile in stig['profile_data']:
                        sqlite_db.run_sqlite_query('''INSERT INTO profiles (profile_id, profile_title, profile_description) 
                                                VALUES (?, ?, ?)''', [profile['profile_id'], profile['profile_title'], profile['profile_description']
                                                                    ])
                        for profile_vuln in profile['vulns']:
                            sqlite_db.run_sqlite_query('''INSERT INTO profile_vulns (profile_id, vuln_id) 
                                                VALUES (?, ?)''', [profile['profile_id'], profile_vuln
                                                                    ])
                                                    
                        for vuln in stig['group_data']:
                            sqlite_db.run_sqlite_query('''INSERT INTO vulns (vuln_id, vuln_title, vuln_description, 
                                                                            vuln_rule_id, vuln_rule_severity, vuln_rule_weight, 
                                                                            vuln_rule_version, vuln_rule_title, vuln_rule_description, 
                                                                            vuln_rule_fix_text, vuln_rule_check) 
                                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', [vuln['vuln_id'], vuln['vuln_title'],
                                                                                                vuln['vuln_description'], vuln['rule_title'], 
                                                                                                vuln['rule_severity'], vuln['rule_weight'], 
                                                                                                vuln['rule_version'], vuln['rule_title'], 
                                                                                                vuln['rule_description'], vuln['rule_fix_text'], 
                                                                                                vuln['rule_check']])
                            for cci in vuln['rule_cci']:
                                sqlite_db.run_sqlite_query('''INSERT INTO vuln_cci (vuln_id, cci_id) 
                                                VALUES (?, ?)''', [vuln['vuln_id'], cci])

                        sqlite_db.sqlite_commit()
                else:
                    sqlite_db.sqlite_key = 'password'
                    sqlite_db.database_encrypted = True
                    sqlite_db.sqlite_connect(application_path + "/" + stig_filename + ".scl")
                    ver = sqlite_db.run_sqlite_query('''Select * From app''', []).get_sqlite_results()
                    #print (ver)

        return ({'error': False}) 

    def get_stig_data(self, stigname):
        stig_folder = 'STIGs'
        zip_file = zipfile.ZipFile('STIGs/' + stigname,'r')

        profile_list = []

        for name in zip_file.namelist():
            if '.xml' in name:
                filename = os.path.basename(name)
                filedirectory = os.path.dirname(name)
                zip_file.extract(name, stig_folder)

                shutil.copy('{0}/{1}'.format(stig_folder, name), '{0}/{1}'.format(stig_folder, filename))
                shutil.rmtree('{0}/{1}'.format(stig_folder, filedirectory))

                xmlns = "{http://checklists.nist.gov/xccdf/1.1}"
                try:
                    xml = ET.parse('{0}/{1}'.format(stig_folder,filename))
                except Exception:
                    print ("Error, unable to parse XML document.  Are you sure that's XCCDF?")

                tree = ET.ElementTree(file='{0}/{1}'.format(stig_folder,filename))
                try:
                    tree = ET.ElementTree(file='{0}/{1}'.format(stig_folder,filename))           
                except Exception:
                    print ("Error processing data.")

                root = tree.getroot()
                stig_list =[]
                stig_info = {}

                stig_info['stig_id'] = root.get('id')
                stig_info['stig_title'] = root.find(xmlns + 'title').text
                for status in root.findall(xmlns + 'status'):
                    stig_info['stig_status'] = status.get('date')
                stig_info['stig_description'] = root.find(xmlns + 'description').text
                stig_info['stig_release'] = root.find(xmlns + 'plain-text').text
                stig_info['stig_version'] = root.find(xmlns + 'version').text

                proflie_list = []
                for profile in root.findall(xmlns + 'Profile'):
                    profile_info = {}
                    profile_info['profile_id'] = (profile.get('id'))
                    profile_info['profile_title'] = (profile.find(xmlns + 'title').text)
                    profile_info['profile_description'] = (profile.find(xmlns + 'description').text)

                    vuln_list = []
                    for select_item in profile.findall('{http://checklists.nist.gov/xccdf/1.1}select'):
                        vuln_list.append(select_item.attrib['idref'])
                    profile_info['vulns'] = vuln_list
                    proflie_list.append(profile_info)

                stig_info['profile_data'] = proflie_list

                group_list =[]
                for group in root.findall(xmlns + 'Group'):
                    group_info = {}
                    group_info['vuln_id'] = group.get('id')
                    group_info['vuln_title'] = (group.find(xmlns + 'title').text)
                    group_info['vuln_description'] = (group.find(xmlns + 'description').text)

                    for rule in group.findall(xmlns + 'Rule'):
                        group_info['rule_id'] = (rule.attrib['id'])
                        group_info['rule_severity'] = (rule.attrib['severity'])
                        group_info['rule_weight'] = (rule.attrib['weight'])
                        group_info['rule_version'] = (rule.find(xmlns + 'version').text)
                        group_info['rule_title'] = (rule.find(xmlns + 'title').text)
                        group_info['rule_description'] = (rule.find(xmlns + 'description').text)
                        rule_cci_list = []
                        for cci in rule.findall(xmlns + 'ident'):
                            rule_cci_list.append(cci.text)
                        group_info['rule_cci'] = rule_cci_list
                        group_info['rule_fix_text'] = (rule.find(xmlns + 'fixtext').text)
                        for check in rule.findall(xmlns + 'check'):
                            group_info['rule_check'] = (check.find(xmlns + 'check-content').text)

                    group_list.append(group_info)

                stig_info['group_data'] = group_list
        
        zip_file.close()

        os.remove('{0}/{1}'.format(stig_folder, filename))

        return stig_info

    def get_stig_status(self):
        zip_stig_list = []
        for filename in os.listdir("STIGs/"):
            if '.zip' in filename:
                zip_stig_list.append(filename)
        
        stig_list = []
        for filename in os.listdir("STIGs/"):
            if '.scl' in filename:
                stig_list.append(filename)

        return ({'zip_stig_count':len(zip_stig_list),
                 'zip_stig_list': zip_stig_list,
                 'stig_count':len(stig_list),
                 'stig_list': stig_list
                })

    def get_stig_info(self, sqlite_db, application_path, stig_filename):
        if os.path.isfile(application_path + "/" + stig_filename + ".scl"):
            sqlite_db.sqlite_key = 'password'
            sqlite_db.database_encrypted = True
            sqlite_db.sqlite_connect(application_path + "/" + stig_filename + ".scl")
            stig_result = sqlite_db.run_sqlite_query('''SELECT * FROM  'STIG' ''', []).get_sqlite_results()
            return {'stig':stig_result[0]}

    def get_profile_info(self, sqlite_db, application_path, stig_filename):
        if os.path.isfile(application_path + "/" + stig_filename + ".scl"):
            sqlite_db.sqlite_key = 'password'
            sqlite_db.database_encrypted = True
            sqlite_db.sqlite_connect(application_path + "/" + stig_filename + ".scl")
            profile_result = sqlite_db.run_sqlite_query('''SELECT * FROM  'profiles' ''', []).get_sqlite_results()
            return {'profiles':profile_result}

