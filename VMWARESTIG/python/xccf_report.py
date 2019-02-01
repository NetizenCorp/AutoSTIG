import xml.etree.cElementTree as ET

root = ET.Element("cdf:Benchmark")
doc = ET.SubElement(root, "cdf:TestResult")

rule_result = ET.SubElement(root, "cdf:rule-result").set("version","WN10-00-00000")


tree = ET.ElementTree(root)
tree.write("t.xml", encoding="utf-8", xml_declaration=True)
ET.SubElement(stig_data, "VULN_ATTRIBUTE").text = "Vuln_Num"
