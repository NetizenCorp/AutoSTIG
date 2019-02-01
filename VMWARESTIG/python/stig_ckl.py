import xml.etree.cElementTree as ET

root = ET.Element("CHECKLIST")
doc = ET.SubElement(root, "ASSET")

ET.SubElement(doc, "ROLE").text = "Domain Controller"
ET.SubElement(doc, "ASSET_TYPE").text = "Computing"
ET.SubElement(doc, "HOST_NAME").text = "AP01"
ET.SubElement(doc, "HOST_IP").text = "192.168.110.17"
ET.SubElement(doc, "HOST_MAC").text = "00-0C-29-B1-15-B5"
ET.SubElement(doc, "HOST_GUID").text = ""
ET.SubElement(doc, "HOST_FQDN").text = ""
ET.SubElement(doc, "TECH_AREA").text = ""
ET.SubElement(doc, "TARGET_KEY").text = ""
ET.SubElement(doc, "WEB_OR_DATABASE").text = "false"
ET.SubElement(doc, "WEB_DB_SITE").text = ""
ET.SubElement(doc, "WEB_DB_INSTANCE").text = ""

stigs = ET.SubElement(root, "STIGS")
istigs = ET.SubElement(stigs, "iSTIG")
stig_info = ET.SubElement(istigs, "STIG_INFO")

si_data = ET.SubElement(stig_info, "SI_DATA")
ET.SubElement(si_data, "SID_NAME").text = "version"
ET.SubElement(si_data, "SID_DATA").text = "1"

si_data = ET.SubElement(stig_info, "SI_DATA")
ET.SubElement(si_data, "SID_NAME").text = "classification"
ET.SubElement(si_data, "SID_DATA").text = "UNCLASSIFIED"

si_data = ET.SubElement(stig_info, "SI_DATA")
ET.SubElement(si_data, "SID_NAME").text = "customname"

si_data = ET.SubElement(stig_info, "SI_DATA")
ET.SubElement(si_data, "SID_NAME").text = "stigid"
ET.SubElement(si_data, "SID_DATA").text = "IE_11_STIG"

si_data = ET.SubElement(stig_info, "SI_DATA")
ET.SubElement(si_data, "SID_NAME").text = "description"
ET.SubElement(si_data, "SID_DATA").text = "The Microsoft Internet Explorer 11 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil"

si_data = ET.SubElement(stig_info, "SI_DATA")
ET.SubElement(si_data, "SID_NAME").text = "filename"
ET.SubElement(si_data, "SID_DATA").text = "U_MS_IE11_STIG_V1R13_Manual-xccdf.xml"

si_data = ET.SubElement(stig_info, "SI_DATA")
ET.SubElement(si_data, "SID_NAME").text = "releaseinfo"
ET.SubElement(si_data, "SID_DATA").text = "Release: 13 Benchmark Date: 28 Jul 2017"

si_data = ET.SubElement(stig_info, "SI_DATA")
ET.SubElement(si_data, "SID_NAME").text = "title"
ET.SubElement(si_data, "SID_DATA").text = "Microsoft Internet Explorer 11 Security Technical Implementation Guide"

si_data = ET.SubElement(stig_info, "SI_DATA")
ET.SubElement(si_data, "SID_NAME").text = "uuid"
ET.SubElement(si_data, "SID_DATA").text = "7712f89b-d02e-40d4-990c-931ac9b4a67b"

si_data = ET.SubElement(stig_info, "SI_DATA")
ET.SubElement(si_data, "SID_NAME").text = "notice"
ET.SubElement(si_data, "SID_DATA").text = "terms-of-use"

si_data = ET.SubElement(stig_info, "SI_DATA")
ET.SubElement(si_data, "SID_NAME").text = "source"
ET.SubElement(si_data, "SID_DATA").text = ""

#------------------------------------------------------------------------------------------------


vuln = ET.SubElement(istigs, "VULN")
stig_data = ET.SubElement(vuln, "STIG_DATA")
ET.SubElement(stig_data, "VULN_ATTRIBUTE").text = "Vuln_Num"
ET.SubElement(stig_data, "ATTRIBUTE_DATA").text = "V-46501"

ET.SubElement(vuln, "FINDING_DETAILS").text = "SSC results determined this is not a finding."









tree = ET.ElementTree(root)
tree.write("filename.xml", encoding="utf-8", xml_declaration=True)
