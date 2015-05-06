// ShellInABox.js -- Use XMLHttpRequest to provide an AJAX terminal emulator.
// Copyright (C) 2008-2010 Markus Gutschke <markus@shellinabox.com>
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// In addition to these license terms, the author grants the following
// additional rights:
//
// If you modify this program, or any covered work, by linking or
// combining it with the OpenSSL project's OpenSSL library (or a
// modified version of that library), containing parts covered by the
// terms of the OpenSSL or SSLeay licenses, the author
// grants you additional permission to convey the resulting work.
// Corresponding Source for a non-source form of such a combination
// shall include the source code for the parts of OpenSSL used as well
// as that of the covered work.
//
// You may at your option choose to remove this additional permission from
// the work, or from any part of it.
//
// It is possible to build this program in a way that it loads OpenSSL
// libraries at run-time. If doing so, the following notices are required
// by the OpenSSL and SSLeay licenses:
//
// This product includes software developed by the OpenSSL Project
// for use in the OpenSSL Toolkit. (http://www.openssl.org/)
//
// This product includes cryptographic software written by Eric Young
// (eay@cryptsoft.com)
//
//
// The most up-to-date version of this program is always available from
// http://shellinabox.com
//
//
// Notes:
//
// The author believes that for the purposes of this license, you meet the
// requirements for publishing the source code, if your web server publishes
// the source in unmodified form (i.e. with licensing information, comments,
// formatting, and identifier names intact). If there are technical reasons
// that require you to make changes to the source code when serving the
// JavaScript (e.g to remove pre-processor directives from the source), these
// changes should be done in a reversible fashion.
//
// The author does not consider websites that reference this script in
// unmodified form, and web servers that serve this script in unmodified form
// to be derived works. As such, they are believed to be outside of the
// scope of this license and not subject to the rights or restrictions of the
// GNU General Public License.
//
// If in doubt, consult a legal professional familiar with the laws that
// apply in your country.

// #define XHR_UNITIALIZED 0
// #define XHR_OPEN        1
// #define XHR_SENT        2
// #define XHR_RECEIVING   3
// #define XHR_LOADED      4

if (!Date.now) {
  Date.now = function now() {
    return new Date().getTime();
  };
}

function extend(subClass, baseClass) {
  function inheritance() { }
  inheritance.prototype          = baseClass.prototype;
  subClass.prototype             = new inheritance();
  subClass.prototype.constructor = subClass;
  subClass.prototype.superClass  = baseClass.prototype;
};

// From libwebsockets text.html example
function get_appropriate_ws_url()
{
  var pcol;
  var u = document.URL;

  /*
   * We open the websocket encrypted if this page came on an
   * https:// url itself, otherwise unencrypted
   */

  if (u.substring(0, 5) == "https") {
    pcol = "wss://";
    u = u.substr(8);
  } else {
    pcol = "ws://";
    if (u.substring(0, 4) == "http")
      u = u.substr(7);
  }

  u = u.split('/');

  /* + "/xxx" bit is for IE10 workaround */

  return pcol + u[0] + "/xxx" + window.location.search;
}
function wsOnOpen(evt) {
  this.shell.sendRequest();
}
function wsOnClose(evt) {
  shell.sessionClosed();
}
function wsOnMessage(evt) {
  shell.vt100(evt.data);
//  console.log("wsOnMessage: " + evt.data);
}
function wsOnError(evt) {
  console.log("wsOnError: " + evt.data);
  shell.websocket = null;
  shell.sessionClosed();
}

function ShellInABox(url, container) {
  if (url == undefined) {
    this.rooturl    = document.location.href;
    this.url        = document.location.href.replace(/[?#].*/, '');
  } else {
    this.rooturl    = url;
    this.url        = url;
  }
  if (document.location.hash != '') {
    var hash        = decodeURIComponent(document.location.hash).
                      replace(/^#/, '');
    this.nextUrl    = hash.replace(/,.*/, '');
 //   this.session    = hash.replace(/[^,]*,/, '');
  } else {
    this.nextUrl    = this.url;
//    this.session    = null;
  this.websocket = null;
  }
  this.pendingKeys  = '';
  this.keysInFlight = false;
  this.connected    = false;
  this.superClass.constructor.call(this, container);

  this.connect();

  // We have to initiate the first XMLHttpRequest from a timer. Otherwise,
  // Chrome never realizes that the page has loaded.
/*  setTimeout(function(shellInABox) {
               return function() {
  //               shellInABox.sendRequest();
               };
             }(this), 1);
*/
};
extend(ShellInABox, VT100);

ShellInABox.prototype.sessionClosed = function() {
  try {
    this.connected    = false;
//    if (this.session) {
//      this.session    = undefined;
      if (this.cursorX > 0) {
        this.vt100('\r\n');
      }
      this.vt100('Session closed.');
//    }
    this.showReconnect(true);
  } catch (e) {
  }
};

ShellInABox.prototype.connect = function() {
  var wsUrl = get_appropriate_ws_url();

  if (typeof MozWebSocket != "undefined") {
    this.websocket = new MozWebSocket(wsUrl,
      "shell-protocol");
  } else {
    this.websocket = new WebSocket(wsUrl,
      "shell-protocol");
  }

  this.websocket.shell = this;
  this.websocket.url = wsUrl;
  this.websocket.onopen = wsOnOpen;
  this.websocket.onclose = wsOnClose;
  this.websocket.onmessage = wsOnMessage;
  this.websocket.onerror = wsOnError;
};
ShellInABox.prototype.reconnect = function() {
  this.showReconnect(false);
//  if (!this.session) {
//    if (document.location.hash != '') {
      // A shellinaboxd daemon launched from a CGI only allows a single
      // session. In order to reconnect, we must reload the frame definition
      // and obtain a new port number. As this is a different origin, we
      // need to get enclosing page to help us.
//      parent.location        = this.nextUrl;
//    } else {
//      if (this.url != this.nextUrl) {
//        document.location.replace(this.nextUrl);
//      } else {
  this.connect();
        this.pendingKeys     = '';
        this.keysInFlight    = false;
        this.reset(true);
        this.sendRequest();
//      }
//    }
//  }
  return false;
};

ShellInABox.prototype.sendRequest = function(request) {
  if (!this.websocket || this.websocket.readyState != WebSocket.OPEN) {
    return;
  }

/*
  var content                = 'width=' + this.terminalWidth +
                               '&height=' + this.terminalHeight +
                               (this.session ? '&session=' +
                                encodeURIComponent(this.session) : '&rooturl='+
                                encodeURIComponent(this.rooturl));
  this.websocket.send(content);
  */
  var content                = 'S ' + this.terminalWidth +
                               ' ' + this.terminalHeight;
  this.websocket.send(content);
};

ShellInABox.prototype.sendKeys = function(keys) {
  //if (!this.connected) {
  if (!this.websocket || this.websocket.readyState != WebSocket.OPEN) {
    return;
  }
  //if (this.keysInFlight || this.session == undefined) {
  if (this.keysInFlight) {
    this.pendingKeys          += keys;
  } else {
//    this.keysInFlight          = true;
    keys                       = this.pendingKeys + keys;
    this.pendingKeys           = '';
   // var request                = new XMLHttpRequest();
   /*
    var content                = 'width=' + this.terminalWidth +
                                 '&height=' + this.terminalHeight +
                                 '&session=' +encodeURIComponent(this.session)+
                                 '&keys=' + encodeURIComponent(keys);
                 */
    /*request.onreadystatechange = function(shellInABox) {
      return function() {
               try {
                 return shellInABox.keyPressReadyStateChange(request);
               } catch (e) {
               }
             }
      }(this);
    */
  this.websocket.send('K ' + keys);
  }
};

ShellInABox.prototype.keysPressed = function(ch) {
  var hex = '0123456789ABCDEF';
  var s   = '';
  for (var i = 0; i < ch.length; i++) {
    var c = ch.charCodeAt(i);
    if (c < 128) {
      s += hex.charAt(c >> 4) + hex.charAt(c & 0xF);
    } else if (c < 0x800) {
      s += hex.charAt(0xC +  (c >> 10)       ) +
           hex.charAt(       (c >>  6) & 0xF ) +
           hex.charAt(0x8 + ((c >>  4) & 0x3)) +
           hex.charAt(        c        & 0xF );
    } else if (c < 0x10000) {
      s += 'E'                                 +
           hex.charAt(       (c >> 12)       ) +
           hex.charAt(0x8 +  (c >> 10) & 0x3 ) +
           hex.charAt(       (c >>  6) & 0xF ) +
           hex.charAt(0x8 + ((c >>  4) & 0x3)) +
           hex.charAt(        c        & 0xF );
    } else if (c < 0x110000) {
      s += 'F'                                 +
           hex.charAt(       (c >> 18)       ) +
           hex.charAt(0x8 +  (c >> 16) & 0x3 ) +
           hex.charAt(       (c >> 12) & 0xF ) +
           hex.charAt(0x8 +  (c >> 10) & 0x3 ) +
           hex.charAt(       (c >>  6) & 0xF ) +
           hex.charAt(0x8 + ((c >>  4) & 0x3)) +
           hex.charAt(        c        & 0xF );
    }
  }
  this.sendKeys(s);
};

ShellInABox.prototype.resized = function(w, h) {
  // Do not send a resize request until we are fully initialized.
  if (this.websocket && this.websocket.readyState == WebSocket.OPEN) {
 // console.log("Resize: " + this.terminalWidth + " " + this.terminalHeight);
    this.websocket.send('S ' + this.terminalWidth + ' ' + this.terminalHeight);
  }
};

ShellInABox.prototype.toggleSSL = function() {
  if (document.location.hash != '') {
    if (this.nextUrl.match(/\?plain$/)) {
      this.nextUrl    = this.nextUrl.replace(/\?plain$/, '');
    } else {
      this.nextUrl    = this.nextUrl.replace(/[?#].*/, '') + '?plain';
    }
    if (!this.session) {
      parent.location = this.nextUrl;
    }
  } else {
    this.nextUrl      = this.nextUrl.match(/^https:/)
           ? this.nextUrl.replace(/^https:/, 'http:').replace(/\/*$/, '/plain')
           : this.nextUrl.replace(/^http/, 'https').replace(/\/*plain$/, '');
  }
  if (this.nextUrl.match(/^[:]*:\/\/[^/]*$/)) {
    this.nextUrl     += '/';
  }
  if (this.session && this.nextUrl != this.url) {
    alert('This change will take effect the next time you login.');
  }
};

ShellInABox.prototype.extendContextMenu = function(entries, actions) {
  // Modify the entries and actions in place, adding any locally defined
  // menu entries.
  var oldActions            = [ ];
  for (var i = 0; i < actions.length; i++) {
    oldActions[i]           = actions[i];
  }
  for (var node = entries.firstChild, i = 0, j = 0; node;
       node = node.nextSibling) {
    if (node.tagName == 'LI') {
      actions[i++]          = oldActions[j++];
      if (node.id == "endconfig") {
        node.id             = '';
        if (typeof serverSupportsSSL != 'undefined' && serverSupportsSSL &&
            !(typeof disableSSLMenu != 'undefined' && disableSSLMenu)) {
          // If the server supports both SSL and plain text connections,
          // provide a menu entry to switch between the two.
          var newNode       = document.createElement('li');
          var isSecure;
          if (document.location.hash != '') {
            isSecure        = !this.nextUrl.match(/\?plain$/);
          } else {
            isSecure        =  this.nextUrl.match(/^https:/);
          }
          newNode.innerHTML = (isSecure ? '&#10004; ' : '') + 'Secure';
          if (node.nextSibling) {
            entries.insertBefore(newNode, node.nextSibling);
          } else {
            entries.appendChild(newNode);
          }
          actions[i++]      = this.toggleSSL;
          node              = newNode;
        }
        node.id             = 'endconfig';
      }
    }
  }
  
};

ShellInABox.prototype.about = function() {
  alert("Shell In A Box version " + "2.10 (revision 239)" +
        "\nCopyright 2008-2010 by Markus Gutschke\n" +
        "For more information check http://shellinabox.com" +
        (typeof serverSupportsSSL != 'undefined' && serverSupportsSSL ?
         "\n\n" +
         "This product includes software developed by the OpenSSL Project\n" +
         "for use in the OpenSSL Toolkit. (http://www.openssl.org/)\n" +
         "\n" +
         "This product includes cryptographic software written by " +
         "Eric Young\n(eay@cryptsoft.com)" :
         ""));
};

