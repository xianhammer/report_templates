//-----------------------------------------------------------
// SAM_Accounts.qs
// Parse the SAM hive file for User information, including group memberships.
//
// Based on report_templates/SAM_UserAccounts.qs
// Install: Copy file to report_templates directory
//
// Change history:
//    20190509 - created
//    20190603 - fixed linux issue
//
// References
//
// Author: Christian Hammer, christian_hammer@hotmail.com
//-----------------------------------------------------------
function fred_report_info() {
  var info={report_cat    : "SAM",
            report_name   : "User Accounts, Extended",
            report_author : "Christian Hammer",
            report_desc   : "Report User Accounts",
            fred_api      : 2,
            hive          : "SAM"
  };
  return info;
}

function fred_report_html() {
  var rootKey = "\\Domains\\Account\\Users\\";

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
  println("<div class='title'>"+info.report_name+"</div>");
  println("<div>Path: ",printroot,"</div>");

  // Iterate over all user names
  var nodes = GetRegistryNodes(rootKey+"Names");
  if (!nodes) {
    rootKey = printroot = "\\"+info.hive+rootKey;
    nodes = GetRegistryNodes(rootKey+"Names");
  };

  if (!nodes) {
    println("<p><font color='red'>This registry hive contain no data!</font></p>");
    return;
  }
  var aliases = get_builtin_aliases(rootKey.replace("\\Account\\Users\\","\\Builtin\\Aliases\\"));

  // TODO (Later) Convert following coe to return array of users info.
  // var users = get_users(rootKey, aliases);
  println("<table>");
  for(var i=0;i<nodes.length;i++) {
    // Get user rid stored in "default" key
    var user_rid = GetRegistryKeyValue(String().concat(rootKey,"Names\\",nodes[i]),"");
    user_rid = RegistryKeyTypeToString(user_rid.type);
    println("<tr><td class='title'>",nodes[i]+"</td><td style='vertical-align:bottom'>"+Number(user_rid)+"/"+user_rid+"</td></tr>");

    // RegistryKeyTypeToString returns the rid prepended with "0x". We have to remove that for further processing
    user_rid = String(user_rid).substr(2);

    // Get user's V key and print various infos
    var v_key = GetRegistryKeyValue(String().concat("\\SAM\\Domains\\Account\\Users\\",user_rid),"V");
    print_v_info(v_key.value,"Full name:",0x18);
    print_v_info(v_key.value,"Comment:",0x24);
    print_v_info(v_key.value,"Home directory:",0x48);
    print_v_info(v_key.value,"Home directory drive:",0x54);
    print_v_info(v_key.value,"Logon script path:",0x60);
    print_v_info(v_key.value,"Profile path:",0x6c);

    // Get user's F key
    var f_key = GetRegistryKeyValue(String().concat(rootKey,user_rid),"F");

    print_table_row("Last login time:",RegistryKeyValueToVariant(f_key.value,"filetime",8), "0x"+Number(RegistryKeyValueToVariant(f_key.value, "uint64", 8)).toString(16));
    print_table_row("Last pw change:",RegistryKeyValueToVariant(f_key.value,"filetime",24), "0x"+Number(RegistryKeyValueToVariant(f_key.value, "uint64", 24)).toString(16));

    var lastLoginFailed = RegistryKeyValueToVariant(f_key.value, "uint64", 40);
    if (lastLoginFailed==0)
      print_table_row("Last failed login:","Never", Number(lastLoginFailed).toString(16));
    else
      print_table_row("Last failed login:",RegistryKeyValueToVariant(f_key.value,"filetime",40), "0x"+Number(lastLoginFailed).toString(16));

    var accountExpire = RegistryKeyValueToVariant(f_key.value, "uint64", 32);
    if (accountExpire==0x7FFFFFFFFFFFFFFF)
      print_table_row("Account expires:","Never", "0x7FFFFFFFFFFFFFFF");
    else
      print_table_row("Account expires:",RegistryKeyValueToVariant(f_key.value,"filetime",32), "0x"+Number(accountExpire).toString(16));

    print_table_row("Total logins:", RegistryKeyValueToVariant(f_key.value,"uint16",66));
    print_table_row("Failed logins:", RegistryKeyValueToVariant(f_key.value,"uint16",64));

    var acc_flags=Number(RegistryKeyValueToVariant(f_key.value,"uint16",56));
    var flags = [];
    if (acc_flags&0x0001) flags.push("Disabled");
    if (acc_flags&0x0002) flags.push("HomeDirReq");
    if (acc_flags&0x0004) flags.push("PwNotReq");
    if (acc_flags&0x0008) flags.push("TempDupAcc");
    if (acc_flags&0x0010) flags.push("NormUserAcc");
    if (acc_flags&0x0020) flags.push("MnsAcc");
    if (acc_flags&0x0040) flags.push("DomTrustAcc");
    if (acc_flags&0x0080) flags.push("WksTrustAcc");
    if (acc_flags&0x0100) flags.push("SrvTrustAcc");
    if (acc_flags&0x0200) flags.push("NoPwExpiry");
    if (acc_flags&0x0400) flags.push("AccAutoLock");

    println("<tr><td>Account flags:</td><td>",flags.join(", ")," (",acc_flags,"/0x",acc_flags.toString(16),")</td></tr>");

    // Get password hint if available
    var hint=GetRegistryKeyValue(String().concat(rootKey,user_rid),"UserPasswordHint");
    if(typeof hint !== 'undefined') {
      // Append missing trailing utf16 zero byte
      hint.value.appendByte(0);
      hint.value.appendByte(0);
      print_table_row("Password hint:",RegistryKeyValueToString(hint.value,hint.length));
    } else {
      print_table_row("Password hint:","");
    }

    var groups = aliases.members[user_rid];
    print_table_row("Groups:", groups&&groups.join(", ")||"-");
  };
  println("</table></body></html>");
}

// Generic tools for output
function print_table_row(cell01,cell02, rawCell2) {
  println("<tr><td>",cell01,"</td><td>",cell02,rawCell2?" ("+rawCell2+")":"","</td></tr>");
}

function print_v_info(v_key_value,info_name,str_off) {
  var offset = Number(RegistryKeyValueToVariant(v_key_value,"uint16",str_off))+0x0cc;
  var len = Number(RegistryKeyValueToVariant(v_key_value,"uint16",str_off+4))/2;
  if (len>0) print_table_row(info_name,RegistryKeyValueToVariant(v_key_value,"utf16",offset,len));
  else print_table_row(info_name,"");
}

// Conversion tools
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

// Parse a C structure (from groups)
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