//-----------------------------------------------------------
// SAM_Groups.qs
// Parse the SAM hive file for Group information
//
// Install: Copy file to report_templates directory
//
// Change history:
//    20190509 - created
//    20190603 - fixed linux issue
//
// References
//    https://github.com/appliedsec/forensicscanner/blob/master/plugins/samparse.pl
//
// Author: Christian Hammer, christian_hammer@hotmail.com
//-----------------------------------------------------------
function fred_report_info() {
  var info={report_cat    : "SAM",
            report_name   : "Groups",
            report_author : "Christian Hammer",
            report_desc   : "Report Groups Information",
            fred_api      : 2,
            hive          : "SAM"
  };
  return info;
}

function fred_report_html() {
  var rootKey = "\\Domains\\Builtin\\Aliases\\";

  fred_report_html = function(){}; // Run only once. Trying to accomodate both windows and linux versions.
  var info = fred_report_info();

  println("<html><head>");
  // When copying from FRED to eg. word, some CSS attributes does not transfer properly - like most font information (especially in TD's).
  // Therefore, (some of) these are duplicated as html tags. SIGH!
  println("<style>");
  println("body, table {font-family: 'Courier New'; font-size: 12pt;}");
  println("*.title {font-size: 1.2em; font-weight: bold;}");
  println("td {vertical-align: top;}");
  println("td.title {padding-top: 0.5em;}");
  println("td:not(.title) {padding-left: 1em;}");
  println("div.title {font-size: 1.5em;}");
  println("</style>");
  println("</head><body>");

  var printroot =  "\\"+info.hive+rootKey;
  println("<div class='title'><b>"+info.report_name+"</b></div>");
  println("<div>Path: ",printroot,"</div>");

  // Iterate over all user names
  var nodes = GetRegistryNodes(rootKey);
  if (!nodes) {
    rootKey = printroot = "\\"+info.hive+rootKey;
    nodes = GetRegistryNodes(rootKey);
  };

  var aliases = get_builtin_aliases(rootKey);

  println("<table>");
  for (var key in aliases.groups) {
    var v = aliases.groups[key];
    println("<tr><td class='title' style='vertical-align:bottom'><b>",v.name,"</b> - ",v.id,"</td></tr>");
    println("<tr><td>",v.comment,".</td></tr>");
    println("<tr><td>SIDs: <i>",v.sids.join(", ")||"n/a","</i></td></tr>");
  };
  println("</table></body></html>");
}

function type_length(type, length){
  var type_size = {"int8":1,"uint8":1,
                  "int16":2,"uint16":2,
                  "int32":4,"uint32":4,
                  "int64":8,"uint64":8,
                  "unixtime":4,"filetime":8,
                  "ascii":function(){return length},
                  "utf16":function(){return length/2}};
  var l = type_size[type];
  return typeof(l)=="function"?l():l;
};
function toUTF16(value, offset, length){
  return String(RegistryKeyValueToVariant(value, "utf16", offset, length/2));
};
function toAscii(value, offset, length){
  return String(RegistryKeyValueToVariant(value, "ascii", offset, length));
};
function toNumberBigEndian(value, type, offset, length){
  // FIX FOR RegistryKeyValueToVariant with <endianess> argument always returning "null"!!!
  var end = (offset||0) + (length||type_length(type));
  for (var r=0, i=offset;i<end;++i) r = (r<<8) + value[i];
  return r;
};
function toNumber(value, type, offset, length){
  return Number(RegistryKeyValueToVariant(value, type, offset||0, length||type_length(type)));
};
function toNumberArray(value, type, offset, length){
  if (length===undefined) length = value.length;
  var delta = type_length(type);
  var end = (offset||0) + length;
  for (var out=[],i=offset||0; i<end; i+=delta) out.push(toNumber(value, type, i, delta));
  return out;
};

function toSID(value, offset, length){
  var sid = {
    revision: value[offset+0],
    dashes: value[offset+1],
    idauth: toNumberBigEndian(value, "uint64", offset+2, 6),
  };

  sid.sub = toNumberArray(value, "uint32", offset+8, 4*(sid.dashes-1));
  if (length>12) sid.rid = toNumber(value, "uint32", offset+8+4*sid.dashes, 4);

  sid.toString = function(){
    var o = ["S", this.revision, this.idauth].concat(this.sub);
    if (this.rid!==undefined) o.push(this.rid);
    return o.join("-");
  };
  return sid;
};

function parseC(value, length){
  var values = toNumberArray(value, "uint32", 0, 0x34);
  var C = {
    nbSids: values[12],
    name: toUTF16(value, 0x34+values[4], values[5]),
    comment: toUTF16(value, 0x34+values[7], values[8]),
    sids: []
  };

  for (var i=0, count=0; i<C.nbSids; ++i){
    var offset = 0x34+values[10] + count;
    var type = toNumber(value, "uint32", offset);
    switch (type){
      case 0x101:
        if (value[offset]==0) ++offset;
        C.sids.push(toSID(value, offset, 12));
        count += 12;
        break;
      case 0x501:
        C.sids.push(toSID(value, offset, 28));
        count += 28;
        break;
      default:
        C.sids.push({offset:offset, count:count});
        break;
    };
  };

  return C;
};
function get_builtin_aliases_groups(rootKey){
  var out = {};
  var nodes = GetRegistryNodes(rootKey+"Names");
  for(var i=0;i<nodes.length;i++) {
    var key = rootKey+"Names\\"+ nodes[i];
    var id = GetRegistryKeyValue(key,"");
    id = String(RegistryKeyTypeToString(id.type)).substr(2); // HEX VALUE!
    out[id] = {name:nodes[i], key:id, toString: function(){return this.name+" ("+this.key+")"}};
  };
  return out;
};
function get_builtin_aliases_members(rootKey, groups){
  var out = {};
  var nodes = GetRegistryNodes(rootKey+"Members");
  for(var i=0;i<nodes.length;++i) {
    var key = rootKey+"Members\\"+ nodes[i];
    var subnodes = GetRegistryNodes(key);
    if (!subnodes) continue;
    for (var j=0;j<subnodes.length;++j){
      var a = toNumberArray(GetRegistryKeyValue(key+"\\"+subnodes[j],"").value, "uint32");
      out[subnodes[j]] = a;
      for (var k=0;k<a.length; ++k){
        var hexKey = ("00000000"+a[k].toString(16)).substr(-8);
        a[k] = groups&&groups[hexKey];
        a[k].toString = function(){ return this.name+" ("+this.key+")"}
      };
    };
  };
  return out;
};
function get_builtin_aliases(rootKey){
  var groups = get_builtin_aliases_groups(rootKey);
  var out = {
    path: rootKey,
    members: get_builtin_aliases_members(rootKey, groups),
    groups: {}
  };

  var nodes = GetRegistryNodes(rootKey);
  for(var i=0;i<nodes.length;i++) {
    var key = nodes[i];
    var path = rootKey+key;
    var C = GetRegistryKeyValue(path,"C");
    if (!C) continue;

    out.groups[key] = C = parseC(C.value,C.length);
    C.id = key;
    C.path = path;
  };
  return out;
};

// Finally, call the main function - windows version of FRED does not run this automatically...
// While linux version need to postpone this to aftaer some initialisation!
if ("GetRegistryNodes" in this)
  fred_report_html();