import os
import sys
import time
import censys.certificates
import censys.ipv4
import censys
 
#finding the subdomains related to given domain
def subdomain_find(domain,censys_id,censys_secret):
    try:
        censys_cert = censys.certificates.CensysCertificates(api_id=censys_id,api_secret=censys_secret)
        cert_query = 'parsed.names: %s' % domain
        cert_search_results = censys_cert.search(cert_query, fields=['parsed.names'])
 
        subdomains = [] #List of subdomains
        for s in cert_search_results:
            subdomains.extend(s['parsed.names'])
 
        return set(subdomains) #removes duplicate values
    except censys.base.CensysUnauthorizedException:
        sys.stderr.write('[+] Censys account details wrong. n')
        exit(1)
    except censys.base.CensysRateLimitExceededException:
        sys.stderr.write('[+] Limit exceeded.')
        exit(1)
def subdomain_filter(domain,subdomains): #If subdomain has *.domain.com It will filter out from list of subdomains.
    return [ subdomain for subdomain in subdomains if '*' not in subdomain and subdomain.endswith(domain) ]
 
def subdomains_list(domain, subdomains): #Take the list and showing structured way.
    if len(subdomains) is 0:
        print('[-] Did not find any subdomain')
        return
 
    print('[*] Found %d unique subdomain n' % (len(subdomains)))
    for subdomain in subdomains:
        print(subdomain)
 
    print('')
def main(domain,censys_id,censys_secret):
    print ("[+] Finding the subdomains of %s " % domain)
    subdomains = subdomain_find(domain,censys_id,censys_secret)
    subdomains = subdomain_filter(domain,subdomains)
    subdomains_list(domain,subdomains)
 
if __name__ == "__main__":
    censys_id = "f7e0ad39-3176-4b73-990c-45ee0f2ea5f8"
    censys_secret = "H01PTdngHt12TAOvTDKZQxLa1qGibFUG"
    domain = raw_input("Enter the domain:")
    main(domain,censys_id,censys_secret)