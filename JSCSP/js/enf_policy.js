
/**
 * JSCSP Policy Enforcement
 * @date        2017.6
 */

function run() {
    var JSCSP = this;

    /**
     * Do some initialization work
     */
    this.init = function () {
        /*  Consts  */
        JSCSP._random = 'jscsp-' + Math.random().toString(36).replace(/\./g, '');
        JSCSP.url_pattern = /^((?:https?|ftp|file):\/\/[A-Za-z0-9&@\-#%?=~_|!:.]+)[\/-A-Za-z0-9+&@#%=~_|]/;
        JSCSP.sandbox_blacklist = ['eval','Proxy'];
        JSCSP.dataread_list = ['document.cookie'];
        JSCSP.datawrite_list = ['document.cookie'];

        /* Format String */
        String.prototype.format = function (replacements) {
            replacements = (typeof replacements === 'object') ? replacements : Array.prototype.slice.call(arguments, 0);
            return formatString(this, replacements);
        }
        var formatString = function (str, replacements) {
            replacements = (typeof replacements === 'object') ? replacements : Array.prototype.slice.call(arguments, 1);
            return str.replace(/\{\{|\}\}|\{(\w+)\}/g, function (m, n) {
                if (m == '{{') { return '{'; }
                if (m == '}}') { return '}'; }
                return replacements[n];
            });
        };

    }

    /**
     * Seal the DOM
     */
    this.seal = function (doc) {
        for (var item in doc) {
            if (typeof doc[item] === 'function') {
                Object.defineProperty(
                    doc, item, { value: doc[item], configurable: false }
                );
            }
        }
        return doc;
    }

    /**
     * Hook function (in a string format)
     */
    this.Sandbox_string = function (func_name) {
        var string = "";
        string += "_{0} = {1};".format(func_name, func_name);
        string += "{0} = function(){".format(func_name, func_name);
        string += "var args = Array.prototype.slice.call(arguments,0);";
        string += "var sandbox = JSON.parse(localStorage['sandbox']);";
        string += "index = sandbox.indexOf('{0}');".format(func_name);
        string += "if(index!=-1)sandbox.splice(index,1);";
        string += "localStorage['sandbox'] = JSON.stringify(sandbox);";
        string += "return _{0}.apply(this,args);}".format(func_name);
        return string
    }

    /**
     * Hook important data (in a string format)
     */
    this.Data_string = function (data_name, action = "read") {
        var tmp = data_name.split('.');
        owner = tmp.slice(0, -1).join('.');
        attr = tmp.slice(-1);

        /* Hook data's read property */
        if (action == "read") {
            var string = "";
            string += "Object.defineProperty({0},'{1}',{configurable: true,".format(owner, attr);
            string += "get:function(){";
            string += "jscsp_data=JSON.parse(localStorage['data_read']);";
            string += "index = jscsp_data.indexOf('{0}');".format(data_name);
            string += "if(index!=-1)jscsp_data.splice(index,1);";
            string += "localStorage['data_read']=JSON.stringify(jscsp_data);";
            if(owner=="document"){
                string += "var e = document.createElement('iframe');";
                string += "document.documentElement.appendChild(e);";
                string += "e.contentDocument.write('null');";
                string += "var n = e.contentDocument.{0};".format(attr);
                string += "return document.documentElement.removeChild(e),n}})";
            }
            else{
                string += "return this.getAttribute('{0}');".format(attr)+"}})";
            }
            return string
        }

        /* Hook data's write property */
        else if (action == "write") {
            var string = "";
            string += "Object.defineProperty({0},'{1}',{configurable: true,".format(owner, attr);
            string += "set:function(value){";
            string += "jscsp_data=JSON.parse(localStorage['data_write']);";
            string += "index = jscsp_data.indexOf('{0}');".format(data_name);
            string += "if(index!=-1)jscsp_data.splice(index,1);";
            string += "localStorage['data_write']=JSON.stringify(jscsp_data);";
            if(owner=="document"){
                string += "var e = document.createElement('iframe');";
                string += "document.documentElement.appendChild(e);";
                string += "e.contentDocument.write('null');";
                string += "e.contentDocument.{0} = value;".format(attr);
                string += "document.documentElement.removeChild(e);}})";
            }
            else{
                string += "this.setAttribute({0},value);".format(attr)+"}})";
            }
            return string
        }
    }

    /**
     * Excute javascript code in the origin page
     */
    this.execute = function (code) {
        var script = JSCSP.doc.createElement('script');
        script.setAttribute("class","jscsp-hook");
        var code = JSCSP.doc.createTextNode(code);
        script.appendChild(code);
        JSCSP.doc.head.appendChild(script);
    }

    /**
     * Remove DOM elements with "allow=false"
     */
    this.filter = function(){
        elements = JSCSP.doc.querySelectorAll("*");
        for (var i = 0; i < elements.length; i++) { 
            if(elements[i].getAttribute("allow")=="false"){
                elements[i].parentNode.removeChild(elements[i]);
            }
        }
    }

    /**
     * Find elements' indexes in their parent node
     */
    this.element_index = function (e) {
        var p = e.parentNode;
        var childs = p.children;
        var hook_count = 0;
        var del_count = 0;
        for (var i = 0; i < childs.length; i++) {
            if(childs.item(i).getAttribute("class")=='jscsp-hook'){
                hook_count++;
            }
            else if(childs.item(i).getAttribute("allow")=='false'){
                del_count++;
            }
            if (e == childs.item(i)) {
                return i-hook_count-del_count;
            }
        }
        return -1;
    }

    /**
     * Get elements' position in the DOM tree
     */
    this.get_position = function (e) {
        if (!e.parentNode) return "document";
        return JSCSP.get_position(e.parentNode) + "," + element_index(e);
    }


    /**
     * Html decode
     */
    this.htmldecode = function(str) {
        str = str.replace(/&lt;?/g, '<');
        str = str.replace(/&gt;?/g, '>');
        return str.replace(/&#(x)?([^&]{1,5});?/g, function($, $1, $2) {
            return String.fromCharCode(parseInt($2, $1 ? 16 : 10));
        });
    };

    /**
     * Enforce policies on script elements
     */
    this.enf_scripts = function(){
        var script_policies = JSCSP.policy['element']['script'];
        if(!script_policies)return;
        var elements = JSCSP.doc.querySelectorAll('script');
        for (var i in elements) {
            if(typeof(elements[i])!="object")continue;
            if(elements[i].getAttribute('class')=='jscsp-hook')continue;
            var e = JSCSP.get_position(elements[i]);
            if(!script_policies['position'] || script_policies['position'].indexOf(e)==-1){
                console.log("Evil script:",elements[i].outerHTML);
                elements[i].setAttribute("allow", "false");
            }
        }
    }

    /**
     * Enforce policies on elements' event-handler
     */
    this.enf_event_handler = function(){
        var element_policies = JSCSP.policy['element'];
        var elements = JSCSP.doc.querySelectorAll('*');
        for (var i in elements) {
            if(typeof(elements[i])!="object")continue;
            for (var j in elements[i].attributes) {
                if (elements[i].attributes[j]&&typeof(elements[i].attributes[j])=="object") {
                    var name = elements[i].attributes[j].name;
                    if (typeof name === 'string' && name.match(/^on/i)) {
                        var e = JSCSP.get_position(elements[i]);
                        if(!element_policies['event-handler-position'] || element_policies['event-handler-position'].indexOf(e)==-1){
                            console.log("Evil event-handler:",elements[i].outerHTML);
                            elements[i].setAttribute("allow", "false");
                        }
                        break;
                    }
                }
            }
        }
    }

    /**
     * Enforce policies on code-reuse payloads
     */
    this.enf_code_reuse = function(){
        var divs =  JSCSP.doc.querySelectorAll("div");
        for(var i=0;i<divs.length;i++){
            // bootstrap bypass
            if (divs[i].getAttribute('data-toggle')=='tooltip') {
                title = this.htmldecode(divs[i].getAttribute('title'));
                if(title.indexOf('<')!=-1 || title.indexOf('>')!=-1){
                    console.log("Evil element:",divs[i].outerHTML);
                    divs[i].setAttribute("allow", "false");
                }
            }
            // jquery mobile bypass
            if (divs[i].getAttribute('data-role')=='popup') {
                id = this.htmldecode(divs[i].getAttribute('id'));
                if(id.indexOf('<')!=-1 || id.indexOf('>')!=-1){
                    console.log("Evil element:",divs[i].outerHTML);
                    divs[i].setAttribute("allow", "false");
                }
            }
            // bootstrap bypass
            if (divs[i].getAttribute('data-toggle')=='tooltip') {
                title = this.htmldecode(divs[i].getAttribute('title'));
                if(title.indexOf('<')!=-1 || title.indexOf('>')!=-1){
                    console.log("Evil element:",divs[i].outerHTML);
                    divs[i].setAttribute("allow", "false");
                }
            }
        }
    }

    this.enforce_policy = function () {

        /* replace "location" with "jscsp_Location" */
        var elements = JSCSP.doc.querySelectorAll('*');
        for (var i in elements) {
            if(typeof(elements[i])!="object")continue;
            if(elements[i].tagName.toLowerCase()=='script'){
                elements[i].innerHTML = elements[i].innerHTML.replace('location.href','jscsp_Location');
                elements[i].innerHTML = elements[i].innerHTML.replace('location','jscsp_Location');
            }
            for (var j in elements[i].attributes) {
                if (elements[i].attributes[j]&&typeof(elements[i].attributes[j])=="object") {
                    var name = elements[i].attributes[j].name;
                    if (typeof name === 'string' && name.match(/^on/i)) {
                        elements[i].setAttribute(name,elements[i].getAttribute(name).replace('location.href','jscsp_Location'));
                        elements[i].setAttribute(name,elements[i].getAttribute(name).replace('location','jscsp_Location'));
                    }
                }
            }
        }

        /* data policies */
        // var data_policies = jscsp_policy['data'];
        // for (var data in data_policies) {
        //     owner = eval(data.split('.').slice(0,-1).join('.'));
        //     prop = data.split('.').slice(-1).join('.');
        //     if (data_policies[data]['read'] == false) {
        //         if (data_policies[data]['write'] == false) {
        //             Object.defineProperty(owner,prop,{
        //                 get: function () {
        //                     return console.log("you can't read "+data);
        //                 },
        //                 set: function (n) {
        //                     return console.log("you can't write "+data);
        //                 }
        //             });
        //         }
        //         else{
        //             Object.defineProperty(owner,prop,{
        //                 get: function () {
        //                     return console.log("you can't read "+data);
        //                 }
        //             });
        //         }
        //     }
        //     else if (data_policies[data]['write'] == false) {
        //         Object.defineProperty(owner,prop,{
        //             set: function (n) {
        //                 return console.log("you can't write "+data);
        //             }
        //         });
        //     }
        // }
        execute(atob("dmFyIGRhdGFfcG9saWNpZXM9anNjc3BfcG9saWN5WyJkYXRhIl07Zm9yKHZhciBkYXRhIGluIGRhdGFfcG9saWNpZXMpe293bmVyPWV2YWwoZGF0YS5zcGxpdCgiLiIpLnNsaWNlKDAsLTEpLmpvaW4oIi4iKSk7cHJvcD1kYXRhLnNwbGl0KCIuIikuc2xpY2UoLTEpLmpvaW4oIi4iKTtpZihkYXRhX3BvbGljaWVzW2RhdGFdWyJyZWFkIl09PWZhbHNlKXtpZihkYXRhX3BvbGljaWVzW2RhdGFdWyJ3cml0ZSJdPT1mYWxzZSl7T2JqZWN0LmRlZmluZVByb3BlcnR5KG93bmVyLHByb3Ase2dldDpmdW5jdGlvbigpe3JldHVybiBjb25zb2xlLmxvZygieW91IGNhbid0IHJlYWQgIitkYXRhKX0sc2V0OmZ1bmN0aW9uKG4pe3JldHVybiBjb25zb2xlLmxvZygieW91IGNhbid0IHdyaXRlICIrZGF0YSl9fSl9ZWxzZXtPYmplY3QuZGVmaW5lUHJvcGVydHkob3duZXIscHJvcCx7Z2V0OmZ1bmN0aW9uKCl7cmV0dXJuIGNvbnNvbGUubG9nKCJ5b3UgY2FuJ3QgcmVhZCAiK2RhdGEpfX0pfX1lbHNle2lmKGRhdGFfcG9saWNpZXNbZGF0YV1bIndyaXRlIl09PWZhbHNlKXtPYmplY3QuZGVmaW5lUHJvcGVydHkob3duZXIscHJvcCx7c2V0OmZ1bmN0aW9uKG4pe3JldHVybiBjb25zb2xlLmxvZygieW91IGNhbid0IHdyaXRlICIrZGF0YSl9fSl9fX07"));

        /* element policies */
        var element_policies = JSCSP.policy['element'];
        for (var selector in element_policies) {
            elements = JSCSP.doc.querySelectorAll(selector);
            plc = element_policies[selector]; 
            for (var i = 0; i < elements.length; i++) { 
                if (plc['allow'] != undefined){
                    console.log("Dangerous tag:",elements[i].outerHTML);
                    elements[i].setAttribute("allow", plc['allow']);
                }
                // src
                if (elements[i].src) {
                    if (!plc['src']){
                        elements[i].setAttribute("allow", "false");
                        continue;
                    }
                    if (plc['src'].indexOf('javascript-uri')==-1) {
                        if (/^javascript/i.test(elements[i].src))
                            elements[i].setAttribute("allow", "false");
                    }
                    if (plc['src'].indexOf('data-uri')==-1) {
                        if (/^data/i.test(elements[i].src))
                            elements[i].setAttribute("allow", "false");
                    }
                    var res = JSCSP.url_pattern.exec(elements[i].src);
                    if (!res) continue;
                    var source = res[1].split('#')[0];
                    if(source==JSCSP.url_pattern.exec(location.href)[1].split('#')[0]){
                        continue;
                    }
                    sources = plc["src"];
                    if (!sources || sources.indexOf(source) == -1) {
                        console.log("Evil src:",elements[i].outerHTML)
                        elements[i].setAttribute("allow", "false");
                    }
                }
                // href
                if (elements[i].href) {
                    if (!plc['href']){
                        elements[i].setAttribute("allow", "false");
                        continue;
                    }
                    if (plc['href'].indexOf('javascript-uri')==-1) {
                        if (/^javascript/i.test(elements[i].href))
                            elements[i].setAttribute("allow", "false");
                    }
                    if (plc['href'].indexOf('data-uri')==-1) {
                        if (/^data/i.test(elements[i].href))
                            elements[i].setAttribute("allow", "false");
                    }
                    var res = JSCSP.url_pattern.exec(elements[i].href);
                    if (!res) continue;
                    var source = res[1].split('#')[0];
                    if(source==JSCSP.url_pattern.exec(location.href)[1].split('#')[0]){
                        continue;
                    }
                    sources = plc["href"];
                    if (!sources || sources.indexOf(source) == -1) {
                        console.log("Evil href:",elements[i].outerHTML);
                        elements[i].setAttribute("allow", "false");
                    }
                }

                // <object data="">
                if (elements[i].tagName.toLowerCase()=='object' && elements[i].getAttribute('data')) {
                    if (!plc['data']){
                        elements[i].setAttribute("allow", "false");
                        console.log("Evil data:",elements[i].outerHTML);
                        continue;
                    }
                    if (plc['data'].indexOf(elements[i].getAttribute('data'))==-1) {
                        console.log("Evil data:",elements[i].outerHTML);
                        elements[i].setAttribute("allow", "false");
                    }
                }

                // <iframe srcdoc="">
                if (elements[i].tagName.toLowerCase()=='iframe' && elements[i].getAttribute('srcdoc')) {
                    if (!plc['srcdoc']){
                        console.log("Evil srcdoc:",elements[i].outerHTML);
                        elements[i].setAttribute("allow", "false");
                        continue;
                    }
                    if (plc['srcdoc'].indexOf(elements[i].getAttribute('srcdoc'))==-1) {
                        console.log("Evil srcdoc:",elements[i].outerHTML);
                        elements[i].setAttribute("allow", "false");
                    }
                }
            }
        }
        JSCSP.enf_code_reuse();
        JSCSP.enf_scripts();
        JSCSP.enf_event_handler();
        
        /* function policies */
        var enforce_code = "";
        var function_policies = JSCSP.policy['sandbox'];
        for (var func in function_policies) {
            if (!function_policies[func]) {
                enforce_code += "delete window['" + func + "'];";
            }
        }
        this.execute(enforce_code);

        /* Remove elements flagged with allow=false */
        JSCSP.filter();
    }


    /* Generate policies for scripts' position */
    this.gen_scripts = function(){
        document.script_position = [];
        var elements = JSCSP.doc.querySelectorAll('script');
        for (var i in elements) {
            if(typeof(elements[i])!="object")continue;
            if(elements[i].getAttribute('class')=='jscsp-hook')continue;
            var e = JSCSP.get_position(elements[i]);
            document.script_position.push(e);
        }
    }

    /* Generate policies for event-handlers' position */
    this.gen_event_handlers = function(){
        document.event_handler_position = [];
        var elements = JSCSP.doc.querySelectorAll('*');
        for (var i in elements) {
            if(typeof(elements[i])!="object")continue;
            for (var j in elements[i].attributes) {
                if (elements[i].attributes[j]&&typeof(elements[i].attributes[j])=="object") {
                    var name = elements[i].attributes[j].name;
                    if (typeof name === 'string' && name.match(/^on/i)) {
                        var e = JSCSP.get_position(elements[i]);
                        document.event_handler_position.push(e);
                        break;
                    }
                }
            }
        }
    }

    /**
     * Preparation for policy generation
     */
    this.prefor_policy_gen = function () {
        // Hook for sandbox policy
        for (var i = 0; i < JSCSP.sandbox_blacklist.length; i++) {
            this.execute(this.Sandbox_string(JSCSP.sandbox_blacklist[i]));
        }
        this.execute("localStorage['sandbox']='{0}';".format(JSON.stringify(JSCSP.sandbox_blacklist)));

        // Hook for data policy
        for (var i = 0; i < JSCSP.dataread_list.length; i++) {
            this.execute(this.Data_string(JSCSP.dataread_list[i], 'read'));
        }
        this.execute("localStorage['data_read']='{0}';".format(JSON.stringify(JSCSP.dataread_list)));

        for (var i = 0; i < JSCSP.datawrite_list.length; i++) {
            //this.execute(this.Data_string(JSCSP.datawrite_list[i], 'write'));
        }
        this.execute("localStorage['data_write']='{0}';".format(JSON.stringify(JSCSP.datawrite_list)));
        
        // Policies for scripts' position
        this.gen_scripts();

        // Policies for event-handlers' position
        this.gen_event_handlers();
    }

    this.hook_redirect = function () {
        // hook location.href
        // We have replaced "location" with "jscsp_location"
        // window.jscsp_Location = {};
        // for(key in location){
        //     jscsp_Location[key] = location[key];
        // }
        // jscsp_Location.toString = function(){return location.href};
        // Object.defineProperty(window,'jscsp_Location',{
        //     set: function(n){
        //         req_src = jscsp_policy['request_src'];
        //         if(!req_src){
        //             console.log("Evil redirection: "+n);
        //         }
        //         else if (/^javascript/i.test(n)) {
        //             console.log("Evil redirection: "+n);
        //         }
        //         else{
        //             var res = /^((?:https?|ftp|file):\/\/[A-Za-z0-9&@\-#%?=~_|!:.]+)[\/-A-Za-z0-9+&@#%=~_|]/.exec(n);
        //             if (res){
        //                 var source = res[1].split('#')[0];
        //                 if (req_src.indexOf(source) == -1) {
        //                     console.log("Evil redirection:",n);
        //                 }
        //                 else {
        //                     location.href = n;
        //                 }
        //             }
        //             else{
        //                 location.href = n;
        //             }
        //         }
        //     }
        // })
        this.execute(atob("d2luZG93LmpzY3NwX0xvY2F0aW9uPXt9O2ZvcihrZXkgaW4gbG9jYXRpb24pe2pzY3NwX0xvY2F0aW9uW2tleV09bG9jYXRpb25ba2V5XX1qc2NzcF9Mb2NhdGlvbi50b1N0cmluZz1mdW5jdGlvbigpe3JldHVybiBsb2NhdGlvbi5ocmVmfTtPYmplY3QuZGVmaW5lUHJvcGVydHkod2luZG93LCJqc2NzcF9Mb2NhdGlvbiIse3NldDpmdW5jdGlvbihuKXtyZXFfc3JjPWpzY3NwX3BvbGljeVsicmVxdWVzdF9zcmMiXTtpZighcmVxX3NyYyl7Y29uc29sZS5sb2coIkV2aWwgcmVkaXJlY3Rpb246ICIrbil9ZWxzZXtpZigvXmphdmFzY3JpcHQvaS50ZXN0KG4pKXtjb25zb2xlLmxvZygiRXZpbCByZWRpcmVjdGlvbjogIituKX1lbHNle3ZhciByZXM9L14oKD86aHR0cHM/fGZ0cHxmaWxlKTpcL1wvW0EtWmEtejAtOSZAXC0jJT89fl98ITouXSspW1wvLUEtWmEtejAtOSsmQCMlPX5ffF0vLmV4ZWMobik7aWYocmVzKXt2YXIgc291cmNlPXJlc1sxXS5zcGxpdCgiIyIpWzBdO2lmKHJlcV9zcmMuaW5kZXhPZihzb3VyY2UpPT0tMSl7Y29uc29sZS5sb2coIkV2aWwgcmVkaXJlY3Rpb246IixuKX1lbHNle2xvY2F0aW9uLmhyZWY9bn19ZWxzZXtsb2NhdGlvbi5ocmVmPW59fX19fSk7"));

        // hook window.open
        // window._open = window.open;
        // window.open = function(){
        //     var args = Array.prototype.slice.call(arguments,0);
        //     url = arguments[0];
        //     req_src = jscsp_policy['request_src'];
        //     if(!req_src){
        //         console.log("Evil redirection: "+url);
        //     }
        //     else if (/^javascript/i.test(url)) {
        //         console.log("Evil redirection: "+url);
        //     }
        //     else{
        //         var res = /^((?:https?|ftp|file):\/\/[A-Za-z0-9&@\-#%?=~_|!:.]+)[\/-A-Za-z0-9+&@#%=~_|]/.exec(url);
        //         if (res){
        //             var source = res[1].split('#')[0];
        //             if (req_src.indexOf(source) == -1) {
        //                 console.log("Evil redirection:",url);
        //             }
        //             else {
        //                 window._open.apply(this,args);
        //             }
        //         }
        //         else{
        //             window._open.apply(this,args);
        //         }
        //     }
        // }
        this.execute(atob("d2luZG93Ll9vcGVuPXdpbmRvdy5vcGVuO3dpbmRvdy5vcGVuPWZ1bmN0aW9uKCl7dmFyIGFyZ3M9QXJyYXkucHJvdG90eXBlLnNsaWNlLmNhbGwoYXJndW1lbnRzLDApO3VybD1hcmd1bWVudHNbMF07cmVxX3NyYz1qc2NzcF9wb2xpY3lbInJlcXVlc3Rfc3JjIl07aWYoIXJlcV9zcmMpe2NvbnNvbGUubG9nKCJFdmlsIHJlZGlyZWN0aW9uOiAiK3VybCl9ZWxzZXtpZigvXmphdmFzY3JpcHQvaS50ZXN0KHVybCkpe2NvbnNvbGUubG9nKCJFdmlsIHJlZGlyZWN0aW9uOiAiK3VybCl9ZWxzZXt2YXIgcmVzPS9eKCg/Omh0dHBzP3xmdHB8ZmlsZSk6XC9cL1tBLVphLXowLTkmQFwtIyU/PX5ffCE6Ll0rKVtcLy1BLVphLXowLTkrJkAjJT1+X3xdLy5leGVjKHVybCk7aWYocmVzKXt2YXIgc291cmNlPXJlc1sxXS5zcGxpdCgiIyIpWzBdO2lmKHJlcV9zcmMuaW5kZXhPZihzb3VyY2UpPT0tMSl7Y29uc29sZS5sb2coIkV2aWwgcmVkaXJlY3Rpb246Iix1cmwpfWVsc2V7d2luZG93Ll9vcGVuLmFwcGx5KHRoaXMsYXJncyl9fWVsc2V7d2luZG93Ll9vcGVuLmFwcGx5KHRoaXMsYXJncyl9fX19Ow=="));
    }

    this.hook_createElement = function () {
        _createElement = document.createElement;
        document.createElement = function (tag) {
            var e = _createElement.call(document, tag);
            Object.defineProperty(e, "src", {
                get: function () {
                    return this.getAttribute("src")
                },
                set: function (n) {
                    src = jscsp_policy['element'][tag]["src"];
                    if(!src){
                        console.log("Evil dynamic src: "+n);
                    }
                    else if (src.indexOf('javascript-uri')==-1) {
                        if (/^javascript/i.test(n))
                            console.log("Evil dynamic src: "+n);
                    }
                    else if (src.indexOf('data-uri')==-1) {
                        if (/^data/i.test(n))
                            console.log("Evil dynamic src: "+n);
                    }
                    else{
                        var res = /^((?:https?|ftp|file):\/\/[A-Za-z0-9&@\-#%?=~_|!:.]+)[\/-A-Za-z0-9+&@#%=~_|]/.exec(n);
                        if (res){
                            var source = res[1].split('#')[0];
                            if (src.indexOf(source) == -1) {
                                console.log("Evil dynamic src:",n);
                            }
                            else {
                                this.setAttribute("src", n);
                            }
                        }
                        else{
                            this.setAttribute("src", n);
                        }
                    }
                }
            })
            Object.defineProperty(e, "href", {
                get: function () {
                    return this.getAttribute("href")
                },
                set: function (n) {
                    href = jscsp_policy['element'][tag]["href"];
                    if(!href){
                        console.log("Evil dynamic href: "+n);
                    }
                    else if (href.indexOf('javascript-uri')==-1) {
                        if (/^javascript/i.test(n))
                            console.log("Evil dynamic href: "+n);
                    }
                    else if (href.indexOf('data-uri')==-1) {
                        if (/^data/i.test(n))
                            console.log("Evil dynamic href: "+n);
                    }
                    else{
                        var res = /^((?:https?|ftp|file):\/\/[A-Za-z0-9&@\-#%?=~_|!:.]+)[\/-A-Za-z0-9+&@#%=~_|]/.exec(n);
                        if (res){
                            var source = res[1].split('#')[0];
                            if (href.indexOf(source) == -1) {
                                console.log("Evil dynamic href:",n);
                            }
                            else {
                                this.setAttribute("href", n);
                            }
                        }
                        else{
                            this.setAttribute("href", n);
                        }
                    }
                }
            })
            if(tag.toLowerCase()=='object'){
                Object.defineProperty(e, "data", {
                    get: function () {
                        return this.getAttribute("data")
                    },
                    set: function (n) {
                        data = jscsp_policy['element'][tag]["data"];
                        if(!data){
                            console.log("Evil dynamic data: "+n);
                        }
                        else if (data.indexOf(n)==-1) {
                            console.log("Evil dynamic data: "+n);
                        }
                    }
                })
            }
            return e;
        }
        this.execute(atob('X2NyZWF0ZUVsZW1lbnQ9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudDtkb2N1bWVudC5jcmVhdGVFbGVtZW50PWZ1bmN0aW9uKHRhZyl7dmFyIGU9X2NyZWF0ZUVsZW1lbnQuY2FsbChkb2N1bWVudCx0YWcpO09iamVjdC5kZWZpbmVQcm9wZXJ0eShlLCJzcmMiLHtnZXQ6ZnVuY3Rpb24oKXtyZXR1cm4gdGhpcy5nZXRBdHRyaWJ1dGUoInNyYyIpfSxzZXQ6ZnVuY3Rpb24obil7c3JjPWpzY3NwX3BvbGljeVsiZWxlbWVudCJdW3RhZ11bInNyYyJdO2lmKCFzcmMpe2NvbnNvbGUubG9nKCJFdmlsIGR5bmFtaWMgc3JjOiAiK24pfWVsc2V7aWYoc3JjLmluZGV4T2YoImphdmFzY3JpcHQtdXJpIik9PS0xKXtpZigvXmphdmFzY3JpcHQvaS50ZXN0KG4pKXtjb25zb2xlLmxvZygiRXZpbCBkeW5hbWljIHNyYzogIituKX19ZWxzZXtpZihzcmMuaW5kZXhPZigiZGF0YS11cmkiKT09LTEpe2lmKC9eZGF0YS9pLnRlc3Qobikpe2NvbnNvbGUubG9nKCJFdmlsIGR5bmFtaWMgc3JjOiAiK24pfX1lbHNle3ZhciByZXM9L14oKD86aHR0cHM/fGZ0cHxmaWxlKTpcL1wvW0EtWmEtejAtOSZAXC0jJT89fl98ITouXSspW1wvLUEtWmEtejAtOSsmQCMlPX5ffF0vLmV4ZWMobik7aWYocmVzKXt2YXIgc291cmNlPXJlc1sxXS5zcGxpdCgiIyIpWzBdO2lmKHNyYy5pbmRleE9mKHNvdXJjZSk9PS0xKXtjb25zb2xlLmxvZygiRXZpbCBkeW5hbWljIHNyYzoiLG4pfWVsc2V7dGhpcy5zZXRBdHRyaWJ1dGUoInNyYyIsbil9fWVsc2V7dGhpcy5zZXRBdHRyaWJ1dGUoInNyYyIsbil9fX19fX0pO09iamVjdC5kZWZpbmVQcm9wZXJ0eShlLCJocmVmIix7Z2V0OmZ1bmN0aW9uKCl7cmV0dXJuIHRoaXMuZ2V0QXR0cmlidXRlKCJocmVmIil9LHNldDpmdW5jdGlvbihuKXtocmVmPWpzY3NwX3BvbGljeVsiZWxlbWVudCJdW3RhZ11bImhyZWYiXTtpZighaHJlZil7Y29uc29sZS5sb2coIkV2aWwgZHluYW1pYyBocmVmOiAiK24pfWVsc2V7aWYoaHJlZi5pbmRleE9mKCJqYXZhc2NyaXB0LXVyaSIpPT0tMSl7aWYoL15qYXZhc2NyaXB0L2kudGVzdChuKSl7Y29uc29sZS5sb2coIkV2aWwgZHluYW1pYyBocmVmOiAiK24pfX1lbHNle2lmKGhyZWYuaW5kZXhPZigiZGF0YS11cmkiKT09LTEpe2lmKC9eZGF0YS9pLnRlc3Qobikpe2NvbnNvbGUubG9nKCJFdmlsIGR5bmFtaWMgaHJlZjogIituKX19ZWxzZXt2YXIgcmVzPS9eKCg/Omh0dHBzP3xmdHB8ZmlsZSk6XC9cL1tBLVphLXowLTkmQFwtIyU/PX5ffCE6Ll0rKVtcLy1BLVphLXowLTkrJkAjJT1+X3xdLy5leGVjKG4pO2lmKHJlcyl7dmFyIHNvdXJjZT1yZXNbMV0uc3BsaXQoIiMiKVswXTtpZihocmVmLmluZGV4T2Yoc291cmNlKT09LTEpe2NvbnNvbGUubG9nKCJFdmlsIGR5bmFtaWMgaHJlZjoiLG4pfWVsc2V7dGhpcy5zZXRBdHRyaWJ1dGUoImhyZWYiLG4pfX1lbHNle3RoaXMuc2V0QXR0cmlidXRlKCJocmVmIixuKX19fX19fSk7aWYodGFnLnRvTG93ZXJDYXNlKCk9PSJvYmplY3QiKXtPYmplY3QuZGVmaW5lUHJvcGVydHkoZSwiZGF0YSIse2dldDpmdW5jdGlvbigpe3JldHVybiB0aGlzLmdldEF0dHJpYnV0ZSgiZGF0YSIpfSxzZXQ6ZnVuY3Rpb24obil7ZGF0YT1qc2NzcF9wb2xpY3lbImVsZW1lbnQiXVt0YWddWyJkYXRhIl07aWYoIWRhdGEpe2NvbnNvbGUubG9nKCJFdmlsIGR5bmFtaWMgZGF0YTogIituKX1lbHNle2lmKGRhdGEuaW5kZXhPZihuKT09LTEpe2NvbnNvbGUubG9nKCJFdmlsIGR5bmFtaWMgZGF0YTogIituKX19fX0pfXJldHVybiBlfTs='));
    }
    this.addhook = function () {
        JSCSP.hook_createElement();
        JSCSP.hook_redirect();
    }
    this.main = function () {
        var xhr = new XMLHttpRequest();
        xhr.open('GET', window.location.href, true);
        xhr.onerror = function () {
            document.documentElement.innerHTML = 'Error getting Page';
        }
        xhr.onload = function () {
			console.time('jscsp');
            if (JSCSP.policy) {
                JSCSP.doc = JSCSP.seal(document.implementation.createHTMLDocument(""));
            }
            else {
                JSCSP.doc = document.implementation.createHTMLDocument("");
            }
            JSCSP.doc.documentElement.innerHTML = this.responseText;
            // Enforce policy
            if (JSCSP.policy) {
                localStorage.jscsp_policy = JSON.stringify(JSCSP.policy);
                JSCSP.execute("var jscsp_policy = JSON.parse(localStorage.getItem('jscsp_policy'));");
                JSCSP.enforce_policy();
                JSCSP.addhook();
            }
            else{
                // Prepare for policy generation
                JSCSP.prefor_policy_gen();
            }
            console.timeEnd('jscsp');
            document.open();
            document.write(JSCSP.doc.documentElement.innerHTML);
            document.close();
        }
        xhr.send();
    }
    this.init();
    // Stop window from rendering
    window.stop();

    // Get policies and enforce them
    chrome.runtime.sendMessage({ 'cmd': 'get_policy' }, function (response) {
        JSCSP.policy = JSON.parse(response);
        JSCSP.main();
    });
}

run();
// if(localStorage['jscsp-hasrun']=="1"){
//     localStorage['jscsp-hasrun']="0";
// }
// else{
//     localStorage['jscsp-hasrun']="1";
//     run();
// }