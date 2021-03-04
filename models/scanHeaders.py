import os
import this
import requests


# In this class we will check each URL what is the missing headers and evaluation information disclosure from
# existing headers
class HeadersRaw:
    def __init__(self):
        self.results = {}

    def raw_headers(self, url):
        r = os.system("curl -i" + url)
        response = requests.get(url)  # To execute get request
        print("\n1. This is Raw Headers:")
        for head, val in response.headers.items():
            print(head + " - " + val)
            self.results[head] = val

        # print(response.headers) (also list of tuple print the results)
        return self.results


def missing_headers(keyHeaders):
    print("\n3. ----- LIST of Missing headers: -----")
    missing_dict = {}
    list_missing_headers = ('Strict-Transport-Security', 'Content-Security-Policy',
                            'X-Frame-Options',
                            'X-Content-Type-Options', 'Referrer-Policy', 'Feature-Policy')
    for header in list_missing_headers:
        if header not in keyHeaders.keys():
            print("\n" + header + "----not in header")
            if header == 'Strict-Transport-Security':
                print(
                    "HTTP Strict Transport Security (HSTS) is a web security policy mechanism which helps to protect secure HTTPS websites against downgrade attacks and cookie hijacking. It allows web servers to declare that web browsers (or other complying user agents) should only interact with it using secure HTTPS connections, and never via the insecure HTTP protocol. "
                    "\n refer link - https://scotthelme.co.uk/hsts-the-missing-link-in-tls/" + "\n Configuration: Strict-Transport-Security: max-age=31536000; includeSubDomains")
                missing_dict[
                    header] = 'HTTP Strict Transport Security (HSTS) is a web security policy mechanism which helps to protect secure HTTPS websites against downgrade attacks and cookie hijacking. It allows web servers to declare that web browsers (or other complying user agents) should only interact with it using secure HTTPS connections, and never via the insecure HTTP protocol. "\n refer link - https://scotthelme.co.uk/hsts-the-missing-link-in-tls/" + "\n Configuration: Strict-Transport-Security: max-age=31536000; includeSubDomains'

            if header == 'Content-Security-Policy':
                print(
                    "Content Security Policy is an effective measure to protect your site from XSS attacks. By "
                    "whitelisting sources of approved content, you can prevent the browser from loading malicious "
                    "assets. \n refer link - https://scotthelme.co.uk/content-security-policy-an-introduction/")
                missing_dict[
                    header] = 'Content Security Policy is an effective measure to protect your site from XSS attacks. By whitelisting sources of approved content, you can prevent the browser from loading malicious "assets. \n refer link - https://scotthelme.co.uk/content-security-policy-an-introduction/'

            if header == 'X-Frame-Options':
                print(
                    "X-Frame-Options tells the browser whether you want to allow your site to be framed or not. "
                    "By preventing a browser from framing your site you can defend against attacks like "
                    "clickjacking. \n refer link - "
                    "https://scotthelme.co.uk/hardening-your-http-response-headers/#x-frame-options. \n Configuration: X-Frame-Options: SAMEORIGIN ")
                missing_dict[
                    header] = 'X-Frame-Options tells the browser whether you want to allow your site to be framed or not. By preventing a browser from framing your site you can defend against attacks like clickjacking. \n refer link -https://scotthelme.co.uk/hardening-your-http-response-headers/#x-frame-options. \n Configuration: X-Frame-Options: SAMEORIGIN'

            if header == 'X-Content-Type-Options':
                print(
                    "X-Content-Type-Options stops a browser from trying to MIME(Man-In-The-Middle) -sniffing the "
                    "content type and forces it to stick with the declared content-type. \n refer link - "
                    "https://scotthelme.co.uk/hardening-your-http-response-headers/#x-content-type-options. \n Configuration: X-Content-Type-Options: nosniff")
                missing_dict[
                    header] = 'X-Content-Type-Options stops a browser from trying to MIME(Man-In-The-Middle) -sniffing the content type and forces it to stick with the declared content-type. \n refer link - https://scotthelme.co.uk/hardening-your-http-response-headers/#x-content-type-options. \n Configuration: X-Content-Type-Options: nosniff'

            if header == 'Referrer-Policy':
                print("Referrer Policy is a new header that allows a site to control how much information the "
                      "browser includes with navigations away from a document and should be set by all sites. \n "
                      "refer link - https://scotthelme.co.uk/a-new-security-header-referrer-policy/")
                missing_dict[
                    header] = 'Referrer Policy is a new header that allows a site to control how much information the browser includes with navigations away from a document and should be set by all sites. \n refer link - https://scotthelme.co.uk/a-new-security-header-referrer-policy/'

            if header == 'Feature-Policy':
                print(
                    "Feature Policy is a new header that allows a site to control which features and APIs can be "
                    "used in the browser. \n refer link - "
                    "https://scotthelme.co.uk/a-new-security-header-feature-policy/ ")
                missing_dict[
                    header] = 'Feature Policy is a new header that allows a site to control which features and APIs can be used in the browser. \n refer link - https://scotthelme.co.uk/a-new-security-header-feature-policy/'

    # print(missing_dict)
    return missing_dict


def evaluate_information_disclosure(keyHeaders):
    print("\n4. WARNING")
    my_dict = {}
    list_of_warning = (
        'X-Frame-Options', 'Strict-Transport-Security', 'Access-Control-Allow-Origin', 'X-XSS-Protection',
        'X-Content-Type-Options', 'Server', 'Cache-Control')
    for header in list_of_warning:
        if header in keyHeaders.keys():
            val = keyHeaders[header]
            print("\n" + header + ' value- ' + val)
            if header == 'X-Frame-Options':
                if val in ['deny', 'sameorigin']:
                    print("This is  NOT information disclosure")
                    print("Configuration: X-Frame-Options: DENY\n")
                    print(
                        "Security Description: The use of 'X-Frame-Options' allows a web page from host B to declare that its content (for example, a button, links, text, etc.) must not be displayed in a frame (<frame> or <iframe>) of another page (e.g., from host A). This is done by a policy declared in the HTTP header and enforced by browser implementations.")
                else:
                    my_dict[
                        header] = 'Security Description: The use of X-Frame-Options allows a web page from host B to declare that its content (for example, a button, links, text, etc.) must not be displayed in a frame (<frame> or <iframe>) of another page (e.g., from host A). This is done by a policy declared in the HTTP header and enforced by browser implementations\n Configuration: X-Frame-Options: DENY\n'

            if header == 'Strict-Transport-Security':
                if keyHeaders[header]:
                    print("This is  NOT information disclosure")
                    print("Configuration: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload")
                else:
                    my_dict[
                        header] = 'Configuration: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'

            if header == 'Access-Control-Allow-Origin':
                if keyHeaders[header] == '*':
                    print("This is information disclosure")
                    print("Configuration: Access-Control-Allow-Origin: http://www.origin.com")
                    my_dict[header] = 'Configuration: Access-Control-Allow-Origin: http://www.origin.com'

            if header == 'X-XSS-Protection':
                if val in ['1', '1; mode=block']:
                    print("This is  NOT information disclosure")
                    print("Configuration: X-XSS-Protection: 1; mode=block")
                    print(
                        "Security Description: This header enables the Cross-site scripting (XSS) filter built into "
                        "most recent web browsers. It's usually enabled by default anyway,so the role of this header "
                        "is to re-enable the filter for this particular website if it was disabled by the user.")
                else:
                    my_dict[
                        header] = 'Security Description: This header enables the Cross-site scripting (XSS) filter ' \
                                  'built into most recent web browsers. Its usually enabled by default anyway,' \
                                  'so the role of this header is to re-enable the filter for this particular website ' \
                                  'if it was disabled by the user.\n Configuration: X-XSS-Protection: 1; mode=block '

            if header == 'X-Content-Type-Options':
                if val == 'nosniff':
                    print("This is  NOT information disclosure")
                    print("Configuration: X-Content-Type-Options: nosniff")
                else:
                    my_dict[header] = 'Configuration: X-Content-Type-Options: nosniff'

            if header == 'Server' or header == 'X-Powered-By':
                if len(val) > 1:
                    print("This is information disclosure")
                    print(
                        "Security Description: Overly long and detailed Server field values increase response latency "
                        "and potentially reveal internal implementation details that might make it (slightly) easier "
                        "for attackers to find and exploit known security holes.")
                    print(
                        "Recommendations: An origin server SHOULD NOT generate a Server field containing needlessly "
                        "fine-grained detail and SHOULD limit the addition of sub products by third parties.")
                    my_dict[
                        header] = 'Security Description: Overly long and detailed Server field values increase ' \
                                  'response latency and potentially reveal internal implementation details that might ' \
                                  'make it (slightly) easier for attackers to find and exploit known security ' \
                                  'holes.\n Recommendations: An origin server SHOULD NOT generate a Server field ' \
                                  'containing needlessly fine-grained detail and SHOULD limit the addition of ' \
                                  'subp roducts by third parties. '

            if header == 'Cache-Control':
                if str(keyHeaders[header]) in ['no-cache', 'no-store', 'must-revalidate']:
                    print("This is  NOT information disclosure")
                    print(
                        "Configuration: Cache-Control: no-cache, no-store, max-age=0, must-revalidate; Pragma: "
                        "no-cache; Expires: 0")
                    print(
                        "Security Description: Caches expose additional potential vulnerabilities, since the contents "
                        "of the cache represent an attractive target for malicious exploitation. Because cache "
                        "contents persist after an HTTP request is complete, an attack on the cache can reveal "
                        "information long after a user believes that the information has been removed from the "
                        "network.Therefore, cache contents need to be protected as sensitive information.")
                    print("Recommendations: Do not store unnecessarily sensitive information in the cache.")
                else:
                    my_dict[
                        header] = 'Security Description: Caches expose additional potential vulnerabilities, ' \
                                  'since the contents of the cache represent an attractive target for malicious ' \
                                  'exploitation. Because cache contents persist after an HTTP request is complete, ' \
                                  'an attack on the cache can reveal information long after a user believes that the ' \
                                  'information has been removed from the network.Therefore, cache contents need to be ' \
                                  'protected as sensitive information.\nRecommendations: Do not store unnecessarily ' \
                                  'sensitive information in the cache.\nConfiguration: Cache-Control: no-cache, ' \
                                  'no-store, max-age=0, must-revalidate; Pragma: no-cache; Expires: 0 '

    return my_dict
