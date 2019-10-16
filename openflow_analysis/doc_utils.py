import urllib
import re


class TableNameQuery():

    def __init__(self, doc_url="http://www.openvswitch.org/support/dist-docs/ovn-northd.8.html"):
        doc = urllib.request.urlopen(doc_url).read().decode("utf-8")
        doc = doc.replace("<u>", "").replace("</u>", "").replace("<b>", "").replace("</b>", "")

        self.doc = doc
        # self.doc = html.fromstring(doc)

    def get_table_name(self, table_id):
        m = re.finditer(".*Table %d\:(.*)" % table_id, self.doc)
        for _m in m:
            return _m

