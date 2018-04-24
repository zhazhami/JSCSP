/**
 * JSCSP Policy Generation
 * 
 * @date        2017.6
 */

! function () {
    var JSCSP = this;

    this.init = function () {
        JSCSP.policy = {
            'request_src': [],
            'sandbox': {},
            'element': {},
            'data': {}
        };
        JSCSP._random = 'jscsp-' + Math.random().toString(36).replace(/\./g, '');
        JSCSP.url_pattern = /^((?:https?|ftp|file):\/\/[A-Za-z0-9&@#\-%?=~_|!:.]+)[\/-A-Za-z0-9+&@#%=~_|]/;
        JSCSP.dangerous_tag = ['iframe','script','object','svg','link','a'];
    }

    // Excute javascript code in origin web page
    this.execute = function (code) {
        var script = document.createElement('script');
        script.setAttribute("class","jscsp-hook");
        var code = document.createTextNode(code);
        script.appendChild(code);
        document.head.insertBefore(script, JSCSP.doc.head.children[0]);
    }

    this.request_src = function () {
        chrome.runtime.sendMessage({
            'cmd': 'get_rq_whitelists'
        }, function (response) {
            JSCSP.policy['request_src'] = JSON.parse(response);
        });
    }

    this.sandbox = function () {
        // functions and objects
        var jscsp_sandbox = JSON.parse(localStorage['sandbox']);
        for (i in jscsp_sandbox) {
            JSCSP.policy['sandbox'][jscsp_sandbox[i]] = false;
        }
    }

    this.element_index = function(e){
        var p = e.parentNode;
        var childs = p.children;
        var hook_count = 0;
        for (var i = 0; i < childs.length; i++) {
            if(childs.item(i).getAttribute("class")=='jscsp-hook'){
                hook_count++;
            }
            if (e == childs.item(i)) {
                return i-hook_count;
            }
        }
        return -1;
    }
    // Get elements' position in DOM tree
    this.get_position = function(e){
        if(!e.parentNode)return "document";
        return get_position(e.parentNode)+","+element_index(e);
    }

    this.element = function () {
        // scripts' position whitelist
        if(!JSCSP.policy['element']['script'])
        JSCSP.policy['element']['script'] = {}
        JSCSP.policy['element']['script']['position'] = document.script_position;

        // elements with event-handler's position whitelist
        JSCSP.policy['element']['event-handler-position'] = document.event_handler_position;
        
        var elements = document.querySelectorAll("*");
        console.log(elements.length);
        for (i in elements) {
            if(typeof(elements[i])!="object")continue;
            tagname = elements[i].tagName.toLowerCase();
            // src
            if (elements[i].src) {
                if (!(tagname in JSCSP.policy['element']))
                    JSCSP.policy['element'][tagname] = {}
                if (!("src" in JSCSP.policy['element'][tagname]))
                    JSCSP.policy['element'][tagname].src = []
                // Pseudo protocal
                if(/^javascript/i.test(elements[i].src)){
                    JSCSP.policy['element'][tagname].src.push("javascript-uri");
                }
                if(/^data/i.test(elements[i].src)){
                    JSCSP.policy['element'][tagname].src.push("data-uri");
                }
                res = JSCSP.url_pattern.exec(elements[i].src);
                if (!res) continue;
                source = res[1].split('#')[0];
                if (JSCSP.policy['element'][tagname].src.indexOf(source) == -1)
                    JSCSP.policy['element'][tagname].src.push(source);
            }
            //href
            if (elements[i].href) {
                if (!(tagname in JSCSP.policy['element']))
                    JSCSP.policy['element'][tagname] = {}
                if (!("href" in JSCSP.policy['element'][tagname]))
                    JSCSP.policy['element'][tagname].href = []
                // Pseudo protocal
                if(/^javascript/i.test(elements[i].href)){
                    JSCSP.policy['element'][tagname].href.push("javascript-uri");
                }
                if(/^data/i.test(elements[i].href)){
                    JSCSP.policy['element'][tagname].href.push("data-uri");
                }
                res = JSCSP.url_pattern.exec(elements[i].href);
                if (!res) continue;
                source = res[1].split('#')[0];
                if (JSCSP.policy['element'][tagname].href.indexOf(source) == -1)
                    JSCSP.policy['element'][tagname].href.push(source);
            }
            // data
            if (tagname=='object' && elements[i].getAttribute('data')) {
                if (!(tagname in JSCSP.policy['element']))
                    JSCSP.policy['element'][tagname] = {}
                if (!("data" in JSCSP.policy['element'][tagname]))
                    JSCSP.policy['element'][tagname].data = []
                data = elements[i].getAttribute('data');
                if (JSCSP.policy['element'][tagname].data.indexOf(data) == -1)
                    JSCSP.policy['element'][tagname].data.push(data);
            }
            // srcdoc
            if (tagname=='iframe' && elements[i].getAttribute('srcdoc')) {
                if (!(tagname in JSCSP.policy['element']))
                    JSCSP.policy['element'][tagname] = {}
                if (!("srcdoc" in JSCSP.policy['element'][tagname]))
                    JSCSP.policy['element'][tagname].srcdoc = []
                srcdoc = elements[i].getAttribute('srcdoc');
                if (JSCSP.policy['element'][tagname].srcdoc.indexOf(srcdoc) == -1)
                    JSCSP.policy['element'][tagname].srcdoc.push(srcdoc);
            }
        }
        // Add policies for dangerous_tags
        var tags = JSCSP.dangerous_tag;
        for (i in tags) {
            if(!document.querySelector(tags[i])){
                JSCSP.policy['element'][tags[i]] = {'allow':false};
            }
        }

    }
    this.data = function () {
        // Data read
        var data_read = JSON.parse(localStorage['data_read']);
        for (i in data_read) {
            if (!JSCSP.policy['data'][data_read[i]]) {
                JSCSP.policy['data'][data_read[i]] = {};
            }
            JSCSP.policy['data'][data_read[i]]['read'] = false;
        }
        // Data write
        var data_write = JSON.parse(localStorage['data_write']);
        for (i in data_write) {
            if (!JSCSP.policy['data'][data_write[i]]) {
                JSCSP.policy['data'][data_write[i]] = {};
            }
            JSCSP.policy['data'][data_write[i]]['write'] = false;
        }
    }
    chrome.runtime.onMessage.addListener(
        function (message, sender, sendResponse) {
            if (message.cmd == 'gen_policy') {
                console.time('jscsp');
                this.init();
                this.sandbox();
                this.element();
                this.data();
                console.timeEnd('jscsp');
                chrome.runtime.sendMessage({
                    'cmd': 'set_policy',
                    'value': JSON.stringify(JSCSP.policy)
                }, function (response) {
                });
            }
        }
    );
}();