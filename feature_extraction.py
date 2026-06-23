from urllib.parse import urlparse
from datetime import datetime

import re
import socket
import requests
import dns.resolver
import whois

from ipwhois import IPWhois

def extract_lexical_features(url):

    features = {}

    features["qty_dot_url"] = url.count(".")
    features["qty_hyphen_url"] = url.count("-")
    features["qty_underline_url"] = url.count("_")
    features["qty_slash_url"] = url.count("/")
    features["qty_questionmark_url"] = url.count("?")
    features["qty_equal_url"] = url.count("=")
    features["qty_at_url"] = url.count("@")
    features["qty_and_url"] = url.count("&")
    features["qty_exclamation_url"] = url.count("!")
    features["qty_space_url"] = url.count(" ")
    features["qty_tilde_url"] = url.count("~")
    features["qty_comma_url"] = url.count(",")
    features["qty_plus_url"] = url.count("+")
    features["qty_asterisk_url"] = url.count("*")
    features["qty_hashtag_url"] = url.count("#")
    features["qty_dollar_url"] = url.count("$")
    features["qty_percent_url"] = url.count("%")

    features["length_url"] = len(url)

    return features

def parse_url(url):

    parsed = urlparse(url)

    domain = parsed.netloc
    params = parsed.query

    path = parsed.path
    parts = path.split("/")

    directory = ""
    file_name = ""

    if len(parts) == 2:
     file_name = parts[1]
 
    if len(parts) >= 3:
        directory = "/" + parts[1] + "/"
        file_name = parts[-1]

    return {
        "domain": domain,
        "directory": directory,
        "file": file_name,
        "params": params
    }

# Function to extract domain features 
def extract_domain_features(domain):

    features = {}

    features["qty_dot_domain"] = domain.count(".")
    features["qty_hyphen_domain"] = domain.count("-")
    features["qty_underline_domain"] = domain.count("_")
    features["qty_slash_domain"] = domain.count("/")
    features["qty_questionmark_domain"] = domain.count("?")
    features["qty_equal_domain"] = domain.count("=")
    features["qty_at_domain"] = domain.count("@")
    features["qty_and_domain"] = domain.count("&")
    features["qty_exclamation_domain"] = domain.count("!")
    features["qty_space_domain"] = domain.count(" ")
    features["qty_tilde_domain"] = domain.count("~")
    features["qty_comma_domain"] = domain.count(",")
    features["qty_plus_domain"] = domain.count("+")
    features["qty_asterisk_domain"] = domain.count("*")
    features["qty_hashtag_domain"] = domain.count("#")
    features["qty_dollar_domain"] = domain.count("$")
    features["qty_percent_domain"] = domain.count("%")

    vowels = "aeiou"

    features["qty_vowels_domain"] = sum(
        1 for c in domain.lower()
        if c in vowels
    )

    features["domain_length"] = len(domain)

    return features

# extract directory features
def extract_directory_features(directory):

    features = {}

    features["qty_dot_directory"] = directory.count(".")
    features["qty_hyphen_directory"] = directory.count("-")
    features["qty_underline_directory"] = directory.count("_")
    features["qty_slash_directory"] = directory.count("/")
    features["qty_questionmark_directory"] = directory.count("?")
    features["qty_equal_directory"] = directory.count("=")
    features["qty_at_directory"] = directory.count("@")
    features["qty_and_directory"] = directory.count("&")
    features["qty_exclamation_directory"] = directory.count("!")
    features["qty_space_directory"] = directory.count(" ")
    features["qty_tilde_directory"] = directory.count("~")
    features["qty_comma_directory"] = directory.count(",")
    features["qty_plus_directory"] = directory.count("+")
    features["qty_asterisk_directory"] = directory.count("*")
    features["qty_hashtag_directory"] = directory.count("#")
    features["qty_dollar_directory"] = directory.count("$")
    features["qty_percent_directory"] = directory.count("%")

    features["directory_length"] = len(directory)

    return features

# Extract File features
def extract_file_features(file_name):

    features = {}

    features["qty_dot_file"] = file_name.count(".")
    features["qty_hyphen_file"] = file_name.count("-")
    features["qty_underline_file"] = file_name.count("_")
    features["qty_slash_file"] = file_name.count("/")
    features["qty_questionmark_file"] = file_name.count("?")
    features["qty_equal_file"] = file_name.count("=")
    features["qty_at_file"] = file_name.count("@")
    features["qty_and_file"] = file_name.count("&")
    features["qty_exclamation_file"] = file_name.count("!")
    features["qty_space_file"] = file_name.count(" ")
    features["qty_tilde_file"] = file_name.count("~")
    features["qty_comma_file"] = file_name.count(",")
    features["qty_plus_file"] = file_name.count("+")
    features["qty_asterisk_file"] = file_name.count("*")
    features["qty_hashtag_file"] = file_name.count("#")
    features["qty_dollar_file"] = file_name.count("$")
    features["qty_percent_file"] = file_name.count("%")

    features["file_length"] = len(file_name)

    return features

# Parameter feature extraction
def extract_parameter_features(params):

    features = {}

    features["qty_dot_params"] = params.count(".")
    features["qty_hyphen_params"] = params.count("-")
    features["qty_underline_params"] = params.count("_")
    features["qty_slash_params"] = params.count("/")
    features["qty_questionmark_params"] = params.count("?")
    features["qty_equal_params"] = params.count("=")
    features["qty_at_params"] = params.count("@")
    features["qty_and_params"] = params.count("&")
    features["qty_exclamation_params"] = params.count("!")
    features["qty_space_params"] = params.count(" ")
    features["qty_tilde_params"] = params.count("~")
    features["qty_comma_params"] = params.count(",")
    features["qty_plus_params"] = params.count("+")
    features["qty_asterisk_params"] = params.count("*")
    features["qty_hashtag_params"] = params.count("#")
    features["qty_dollar_params"] = params.count("$")
    features["qty_percent_params"] = params.count("%")

    features["params_length"] = len(params)

    return features

def domain_in_ip(domain):

    ip_pattern = r"^\d+\.\d+\.\d+\.\d+$"

    if re.match(ip_pattern, domain):
        return 1

    return 0

def email_in_url(url):

    email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

    if re.search(email_pattern, url):
        return 1

    return 0
def url_shortened(domain):

    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd"
    ]

    if domain in shorteners:
        return 1

    return 0
def tls_ssl_certificate(url):

    if url.startswith("https://"):
        return 1

    return 0

def qty_redirects(url):

    try:
        response = requests.get(url)

        return len(response.history)

    except:
        return 0
# qty_ip_resolved

def qty_ip_resolved(domain):

    try:
        answers = dns.resolver.resolve(domain, 'A')

        return len(answers)

    except:
        return 0
#qty_name_server

def qty_nameservers(domain):

    try:
        answers = dns.resolver.resolve(domain, 'NS')

        return len(answers)

    except:
        return 0
#qty_mx_server

def qty_mx_servers(domain):

    try:
        answers = dns.resolver.resolve(domain, 'MX')

        return len(answers)

    except:
        return 0
#ttl_hostname
def ttl_hostname(domain):

    try:
        answers = dns.resolver.resolve(domain, 'A')

        return answers.rrset.ttl

    except:
        return 0
#tiime_activation_domain

from datetime import datetime

def time_domain_activation(domain):

    try:

        info = whois.whois(domain)

        creation_date = info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        age = (datetime.now() - creation_date).days

        return age

    except:
        return 0
#time_domain_expiration

from datetime import datetime

def time_domain_expiration(domain):

    try:

        info = whois.whois(domain)

        expiration_date = info.expiration_date

        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        days_left = (expiration_date - datetime.now()).days

        return days_left

    except:
        return 0
#asn_ip

from ipwhois import IPWhois

def asn_ip(domain):

    try:

        ip = socket.gethostbyname(domain)

        obj = IPWhois(ip)

        result = obj.lookup_rdap()

        return int(result["asn"])

    except:
        return 0
#url_google_index
def url_google_index(url):

    return -1
#domain_google_index
def domain_google_index(domain):

    return -1
# Master Function
def extract_all_features(url):

    features = {}

    # URL Features
    features.update(
        extract_lexical_features(url)
    )

    # Parse URL
    components = parse_url(url)

    domain = components["domain"]
    directory = components["directory"]
    file_name = components["file"]
    params = components["params"]

    # Domain Features
    features.update(
        extract_domain_features(domain)
    )

    # Directory Features
    features.update(
        extract_directory_features(directory)
    )

    # File Features
    features.update(
        extract_file_features(file_name)
    )

    # Parameter Features
    features.update(
        extract_parameter_features(params)
    )

    # Other Features
    features["domain_in_ip"] = domain_in_ip(domain)

    features["email_in_url"] = email_in_url(url)

    features["url_shortened"] = url_shortened(domain)

    features["tls_ssl_certificate"] = tls_ssl_certificate(url)

    features["qty_redirects"] = qty_redirects(url)

    features["qty_ip_resolved"] = qty_ip_resolved(domain)

    features["qty_nameservers"] = qty_nameservers(domain)

    features["qty_mx_servers"] = qty_mx_servers(domain)

    features["ttl_hostname"] = ttl_hostname(domain)

    features["time_domain_activation"] = (
        time_domain_activation(domain)
    )

    features["time_domain_expiration"] = (
        time_domain_expiration(domain)
    )

    features["asn_ip"] = asn_ip(domain)

    features["url_google_index"] = (
        url_google_index(url)
    )

    features["domain_google_index"] = (
        domain_google_index(domain)
    )

    return features

