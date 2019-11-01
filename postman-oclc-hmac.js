// Postman pre-request script to generate OCLC HMAC signature and authorization header
// Sets Postman environment variable "authheader" to authorization header with HMAC sig
// Copy-paste this script into Pre-request Script area for request or (better) for colleciton
// Then set request header "Authorization" to {{authheader}}

// Adapted from https://github.com/OCLC-Developer-Network/oclc-auth-node
// Replacing node crypto module with Postman crypto-js mutatis mutandis
// Larry Deck, 2019


// Create a Postman environment with these variables
// OR
// Replace all pm.environment.get("{variable}") with associate values for 
// the API you're using

const key = pm.environment.get("WSKEY");
const secret = pm.environment.get("secret");
const principalID = pm.environment.get("principalID");
const principalIDNS = pm.environment.get("principalIDNS");
  


// set DEBUG to true to send debugging messages to Postman console

const DEBUG = false; 



// DO NOT edit anything below this line

const method = pm.request.method;

const debugmessage = function(d, m) {
    if (d) {
        console.log(m);
    }
}

const requrl = pm.request.url;
var querystring = "";


// License Manager API only wants part of the querystring URI encoded

if ( typeof requrl.query.all()[0] !== 'undefined' ) {
  const query = requrl.query.all()[0];
  querystring = query.key + "=" + encodeURIComponent(query.value);
  debugmessage(querystring); 
}
    


oclcHmac = function(method, request_url, options) {

    const q = "\"";
    const qc = "\", ";

    // if nonce & timestamp are supplied as options -- e.g. for testing -- use those, otherwise generate

    const nonce = options && options.nonce ? options.nonce : Math.round(Math.random() * 4294967295);
    
    debugmessage("NONCE : " + nonce);
    
    const timestamp = options && options.timestamp ? options.timestamp : Math.round((new Date()).getTime() / 1000);

    if (options) {
        for (let parameter in options) {
            parameter = options[parameter];
        }
    }


    signature = signed(key, secret, method, timestamp, nonce, querystring);

    debugmessage("SIGNATURE  : " + signature );

    let auth_header = "http://www.worldcat.org/wskey/v2/hmac/v1 "
        + "clientID=" + q + key + qc
        + "timestamp=" + q + timestamp + qc
        + "nonce=" + q + nonce + qc
        + "signature=" + q + signature + qc
        + "principalID=" + q + principalID + qc
        + "principalIDNS=" + q + principalIDNS + "\"";

    debugmessage("AUTH_HEADER : " + auth_header); 
    
	return auth_header;
}

const signed = function(key, secret, method, timestamp, nonce, querystring) {

    let normreq = normalizeRequest(key, method, timestamp, nonce, querystring);

    debugmessage(normreq);

    let hmac = CryptoJS.HmacSHA256(normreq, secret);
    
    return hmac.toString(CryptoJS.enc.Base64);
}


// Postman doesn't like two string literals concatenated on one line, so no "www.oclc.org" + "\n" -- c'est la vie

const normalizeRequest = function(key, method, timestamp, nonce, querystring) {
    
    bodyHash = "";  // holdover from node_auth, may add it back in later
    
    var req = key + "\n"
        + timestamp + "\n"
        + nonce + "\n"
        + bodyHash + "\n"
        + method + "\n"
        + "www.oclc.org\n"
        + "443\n"
        + "/wskey\n";
    if ( querystring.length > 0 ) {
        req += querystring + "\n";
    }
    
    return req;
}

debugmessage(oclcHmac(method, requrl, {}));

pm.environment.set("authheader", (oclcHmac(method, requrl, {})));
