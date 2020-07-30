from pymisp import PyMISP, MISPEvent, MISPObject
from pyaml import yaml
import logging
import datetime


logging.getLogger("pymisp").setLevel(logging.INFO)

with open("credentials.yaml", "r") as creds_file:
    config = yaml.load(creds_file)

misp_url = config["misp"]["misp_url"]
misp_key = config["misp"]["misp_key"]
misp_verifycert = config["misp"]["misp_verifycert"]

# This dictionary is used for proper setting information for each MISP event (used in _processor functions)
info_dict = {
    "accs": "Compromised account",
    "cards": "Compromised card",
    "imei": "Compromised mobile device",
    "mules": "Money mule",
    "ddos": "DDoS attack",
    "domain": "Domain",
    "ssl": "SSL",
    "phishing": "Phishing",
    "advert": "Advertising",
    "mobileapp": "Mobile app",
    "phishingkit": "Phishing kit",
    "tornodes": "TOR node",
    "proxy": "Open Proxy server",
    "socks": "Private/Botnet SOCKS",
    "leaks": "Leak",
    "hacktivism": "Hacktivism operation",
    "sample": "Targeted malware",
    "threats": "Threat"
}


def log(str):
    """
    Function for logging
    """
    now = datetime.datetime.now()
    str = "{0:%Y}-{0:%m}-{0:%d} {0:%H}:{0:%M}:{0:%S}\t".format(now) + str
    print(str)


def init(url, key):
    """
    Wrap for MISP instance initialization
    """
    return PyMISP(url, key, misp_verifycert, debug=False, tool='json')


def create_events(json, feed):
    """
    Main entrance function that should be imported from another files
    """
    processor = EventProcessor()
    misp = init(misp_url, misp_key)

    for event in json["data"]["new"]:
        # Looking into 'new' field, parsing each event separately
        # Taking feed name, choosing appropriate processor
        method = getattr(processor, feed + "_processor")
        try:
            misp_event = method(event, feed)
        except KeyError as err:
            log("Error parsing event with json id " + str(event["id"]) + ": " + str(err))
            misp_event = 0

        if misp_event != 0:
            # If the event was created correctly, adding it to the MISP instance object.
            misp.add_event(misp_event)
            log("Event with json-id " + str(event["id"]) + " was created correctly")


class EventProcessor(object):
    """
    Class that contains all feed processors.
    The main idea for all processors is the same, so only the accounts would be commented.
    """
    def valid_ip(self, address):
        """
        Check if input parameter string is IP
        """
        parts = str(address).split(".")
        if len(parts) != 4:
            return False
        for item in parts:
            if not 0 <= int(item) <= 255:
                return False
        return True


    def accs_processor(self, event, feed):
        attrs = event["attrs"]
        if attrs["login"] is None:
            return 0

        # Creating misp event object, where all information will be added
        misp_event = MISPEvent()
        misp_event.add_attribute(type="text", value="Group-IB Threat Intelligence: " + info_dict[feed])
        misp_event.info = attrs["login"]

        if attrs["date_detected"] is not None or attrs["date_compromised"] is not None:
            # Creating a MISP object for similar data fields, in this particular case for dates.
            new_object_1 = MISPObject("Incident date")

            # If the json field contains None, the attribute just won't be added by library function
            new_object_1.add_attribute("Date-detected", type="datetime", value=attrs["date_detected"])
            new_object_1.add_attribute("Date-compromised", type="datetime", value=attrs["date_compromised"])

            # Adding object to event
            misp_event.add_object(new_object_1)

        new_object_2 = MISPObject("Compromised account information")

        new_object_2.add_attribute("Login", type="text", value=attrs["login"])
        new_object_2.add_attribute("Password", type="text", value=attrs["password"])
        new_object_2.add_attribute("Domain", type="domain", value=attrs["domain"], to_ids=False)

        misp_event.add_object(new_object_2)

        if attrs["client_ip"] is not None:
            new_object_3 = MISPObject("Client IP information")

            new_object_3.add_attribute("Client-IP", type="ip-src", value=attrs["client_ip"], to_ids=False)
            new_object_3.add_attribute("Client-IP-city", type="text", value=attrs["client_ip_city"])
            new_object_3.add_attribute("Client-IP-country-code", type="text", value=attrs["client_ip_country_code"])
            new_object_3.add_attribute("Client-IP-country-name", type="text", value=attrs["client_ip_country_name"])
            new_object_3.add_attribute("Client-IP-region", type="text", value=attrs["client_ip_region"])
            new_object_3.add_attribute("Client-IP-provider", type="text", value=attrs["client_ip_provider"])
            new_object_3.add_attribute("Client-IP-asn", type="text", value=attrs["client_ip_asn"])

            misp_event.add_object(new_object_3)

        if attrs["cnc_ip"] is not None:
            new_object_4 = MISPObject("C&C information")

            new_object_4.add_attribute("C&C", type="text", value=attrs["cnc"])
            send_ip = True if attrs["cnc_url"] is None else False
            new_object_4.add_attribute("C&C-IP", type="ip-src", value=attrs["cnc_ip"], to_ids=send_ip)
            new_object_4.add_attribute("C&C-IP-city", type="text", value=attrs["cnc_ip_city"])
            new_object_4.add_attribute("C&C-IP-country-code", type="text", value=attrs["cnc_ip_country_code"])
            new_object_4.add_attribute("C&C-IP-country-name", type="text", value=attrs["cnc_ip_country_name"])
            new_object_4.add_attribute("C&C-IP-region", type="text", value=attrs["cnc_ip_region"])
            new_object_4.add_attribute("C&C-IP-provider", type="text", value=attrs["cnc_ip_provider"])
            new_object_4.add_attribute("C&C-IP-asn", type="text", value=attrs["cnc_ip_asn"])
            new_object_4.add_attribute("C&C-domain", type="domain", value=attrs["cnc_domain"], to_ids=True)
            new_object_4.add_attribute("C&C-url", type="url", value=attrs["cnc_url"], to_ids=True)

            misp_event.add_object(new_object_4)

        # Finally, processor returns event with all objects
        return misp_event


    def cards_processor(self, event, feed):
        attrs = event["attrs"]
        if attrs["card_number"] is None:
            return 0

        misp_event = MISPEvent()
        misp_event.add_attribute(type="text", value="Group-IB Threat Intelligence: " + info_dict[feed])
        misp_event.info = attrs["card_number"]

        if attrs["date_detected"] is not None or attrs["date_compromised"] is not None:
            new_object_1 = MISPObject("Incident date")

            new_object_1.add_attribute("Date-detected", type="datetime", value=attrs["date_detected"])
            new_object_1.add_attribute("Date-compromised", type="datetime", value=attrs["date_compromised"])

            misp_event.add_object(new_object_1)

        new_object_2 = MISPObject("Compromised card information")

        new_object_2.add_attribute("Card-number", type="cc-number", value=attrs["card_number"])
        new_object_2.add_attribute("Card-cvv", type="text", value=attrs["card_cvv"])
        if attrs["card_valid_thru"] is not None and len(attrs["card_valid_thru"]) == 4:
            new_object_2.add_attribute("Card-expiration", type="text", value=attrs["card_valid_thru"][:2] + "/" + attrs["card_valid_thru"][2:])
        new_object_2.add_attribute("Card-system", type="text", value=attrs["card_system"])
        new_object_2.add_attribute("Card-type", type="text", value=attrs["card_type"])
        new_object_2.add_attribute("Card-issuer", type="text", value=attrs["card_issuer"])
        new_object_2.add_attribute("Card-issuer-country-code", type="text", value=attrs["card_issuer_country_code"])
        new_object_2.add_attribute("Card-issuer-country-name", type="text", value=attrs["card_issuer_country_name"])

        misp_event.add_object(new_object_2)

        if attrs["owner"] is not None:
            new_object_3 = MISPObject("Person information")

            new_object_3.add_attribute("Name", type="first-name", value=attrs["owner"])
            new_object_3.add_attribute("Country-code", type="text", value=attrs["owner_country_code"])
            new_object_3.add_attribute("State", type="text", value=attrs["owner_state"])
            new_object_3.add_attribute("City", type="text", value=attrs["owner_city"])
            new_object_3.add_attribute("Address", type="text", value=attrs["owner_address"])
            new_object_3.add_attribute("ZIP", type="text", value=attrs["owner_zip"])
            new_object_3.add_attribute("E-mail", type="text", value=attrs["owner_email"])
            new_object_3.add_attribute("Phone", type="phone-number", value=attrs["owner_phone"])

            misp_event.add_object(new_object_3)

        return misp_event


    def imei_processor(self, event, feed):
        attrs = event["attrs"]

        misp_event = MISPEvent()
        misp_event.add_attribute(type = "text", value="Group-IB Threat Intelligence: " + info_dict[feed])
        if attrs["device_imei"] is not None and attrs["device_imei"] != "~":
            misp_event.info = attrs["device_imei"]
        elif attrs["device_iccid"] is not None and attrs["device_iccid"] != "~":
            misp_event.info = attrs["device_iccid"]
        elif attrs["device_imsi"] is not None and attrs["device_imsi"] != "~":
            misp_event.info = attrs["device_imsi"]
        else:
            misp_event.info = "Compromised mobile device info"

        if attrs["date_detected"] is not None or attrs["date_compromised"] is not None:
            new_object_1 = MISPObject("Incident date")

            new_object_1.add_attribute("Date-detected", type="datetime", value=attrs["date_detected"])
            new_object_1.add_attribute("Date-compromised", type="datetime", value=attrs["date_compromised"])

            misp_event.add_object(new_object_1)

        new_object_2 = MISPObject("Compromised mobile device: " + attrs["device_imei"])

        new_object_2.add_attribute("Device-IMEI", type="text", value=attrs["device_imei"])
        new_object_2.add_attribute("Device-ICCID", type="text", value=attrs["device_iccid"])
        new_object_2.add_attribute("Device-IMSI", type="text", value=attrs["device_imsi"])
        new_object_2.add_attribute("Malware", type="text", value=attrs["malware"])
        new_object_2.add_attribute("Cybercrime", type="text", value=attrs["cybercrime"])

        misp_event.add_object(new_object_2)

        if attrs["cnc_ip"] is not None:
            new_object_3 = MISPObject("C&C information")

            new_object_3.add_attribute("C&C", type="text", value=attrs["cnc"])
            send_ip = True if attrs["cnc_url"] is None else False
            new_object_3.add_attribute("C&C-IP", type="ip-src", value=attrs["cnc_ip"], to_ids=send_ip)
            new_object_3.add_attribute("C&C-IP-city", type="text", value=attrs["cnc_ip_city"])
            new_object_3.add_attribute("C&C-IP-country-code", type="text", value=attrs["cnc_ip_country_code"])
            new_object_3.add_attribute("C&C-IP-country-name", type="text", value=attrs["cnc_ip_country_name"])
            new_object_3.add_attribute("C&C-IP-region", type="text", value=attrs["cnc_ip_region"])
            new_object_3.add_attribute("C&C-IP-provider", type="text", value=attrs["cnc_ip_provider"])
            new_object_3.add_attribute("C&C-IP-asn", type="text", value=attrs["cnc_ip_asn"])
            new_object_3.add_attribute("C&C-domain", type="domain", value=attrs["cnc_domain"], to_ids=True)
            new_object_3.add_attribute("C&C-url", type="url", value=attrs["cnc_url"], to_ids=True)

            misp_event.add_object(new_object_3)

        return misp_event


    def mules_processor(self, event, feed): #TODO: Add hash field
        attrs = event["attrs"]
        if attrs["account"] is None and attrs["person"] is None:
            return 0

        misp_event = MISPEvent()
        misp_event.add_attribute(type="text", value="Group-IB Threat Intelligence: " + info_dict[feed])
        misp_event.info = attrs["account"]

        if attrs["date_add"] is not None or attrs["date_incident"] is not None:
            new_object_1 = MISPObject("Incident date")

            new_object_1.add_attribute("Date-add", type="datetime", value=attrs["date_add"])
            new_object_1.add_attribute("Date-incident", type="datetime", value=attrs["date_incident"])

            misp_event.add_object(new_object_1)

        if attrs["account"] is not None:
            new_object_2 = MISPObject("Operator information")

            new_object_2.add_attribute("Account", type="bank-account-nr", value=attrs["account"])
            new_object_2.add_attribute("Operator", type="text", value=attrs["operator"])
            new_object_2.add_attribute("Operator-BIC-ru", type="bic", value=attrs["operator_bic_ru"])
            new_object_2.add_attribute("Operator-BIC", type="bic", value=attrs["operator_bic"])
            new_object_2.add_attribute("Operator-SWIFT", type="text", value=attrs["operator_swift"])
            new_object_2.add_attribute("Operator-IBAN", type="iban", value=attrs["operator_iban"])

            misp_event.add_object(new_object_2)

        if attrs["person"] is not None:
            new_object_3 = MISPObject("Person information")

            new_object_3.add_attribute("Name", type="first-name", value=attrs["person"])
            new_object_3.add_attribute("Information", type="comment", value=attrs["info"])

            misp_event.add_object(new_object_3)

        if attrs["cnc_ip"] is not None:
            new_object_4 = MISPObject("C&C information")

            new_object_4.add_attribute("C&C", type="text", value=attrs["cnc"])
            send_ip = True if attrs["cnc_url"] is None else False
            new_object_4.add_attribute("C&C-IP", type="ip-src", value=attrs["cnc_ip"], to_ids=send_ip)
            new_object_4.add_attribute("C&C-IP-city", type="text", value=attrs["cnc_ip_city"])
            new_object_4.add_attribute("C&C-IP-country-code", type="text", value=attrs["cnc_ip_country_code"])
            new_object_4.add_attribute("C&C-IP-country-name", type="text", value=attrs["cnc_ip_country_name"])
            new_object_4.add_attribute("C&C-IP-region", type="text", value=attrs["cnc_ip_region"])
            new_object_4.add_attribute("C&C-IP-provider", type="text", value=attrs["cnc_ip_provider"])
            new_object_4.add_attribute("C&C-IP-asn", type="text", value=attrs["cnc_ip_asn"])
            new_object_4.add_attribute("C&C-domain", type="domain", value=attrs["cnc_domain"], to_ids=True)
            new_object_4.add_attribute("C&C-url", type="url", value=attrs["cnc_url"], to_ids=True)

            misp_event.add_object(new_object_4)

        return misp_event


    def ddos_processor(self, event, feed):
        attrs = event["attrs"]
        if attrs["target_ip"] is None:
            return 0

        misp_event = MISPEvent()
        misp_event.add_attribute(type="text", value="Group-IB Threat Intelligence: " + info_dict[feed])
        misp_event.info = attrs["target_ip"]

        if attrs["date_reg"] is not None or attrs["date_begin"] is not None or attrs["date_end"] is not None:
            new_object_1 = MISPObject("Incident dates")

            new_object_1.add_attribute("Date-registered", type="datetime", value=attrs["date_reg"])
            new_object_1.add_attribute("Date-begin", type="datetime", value=attrs["date_begin"])
            new_object_1.add_attribute("Date-end", type="datetime", value=attrs["date_end"])

            misp_event.add_object(new_object_1)

        new_object_2 = MISPObject("Target information")

        send_ip = True if attrs["target_url"] is None else False
        new_object_2.add_attribute("Target-IP", type="ip-dst", value=attrs["target_ip"], to_ids=send_ip)
        new_object_2.add_attribute("Target-IP-city", type="text", value=attrs["target_ip_city"])
        new_object_2.add_attribute("Target-IP-country-code", type="text", value=attrs["target_ip_country_code"])
        new_object_2.add_attribute("Target-IP-country-name", type="text", value=attrs["target_ip_country_name"])
        new_object_2.add_attribute("Target-IP-region", type="text", value=attrs["target_ip_region"])
        new_object_2.add_attribute("Target-IP-provider", type="text", value=attrs["target_ip_provider"])
        new_object_2.add_attribute("Target-IP-asn", type="text", value=attrs["target_ip_asn"])
        new_object_2.add_attribute("Target-domain", type="domain", value=attrs["target_domain"], to_ids=True)
        new_object_2.add_attribute("Target-url", type="url", value=attrs["target_url"], to_ids=False)
        new_object_2.add_attribute("Target-shared-hosting", type="text", value=attrs["target_shared"])
        new_object_2.add_attribute("Target-hosted-domains", type="text", value=attrs["target_domains_cnt"])
        new_object_2.add_attribute("Target-category", type="text", value=attrs["target_category"])
        new_object_2.add_attribute("Target-port", type="port", value=attrs["target_port"])
        new_object_2.add_attribute("DDoS attack type", type="text", value=attrs["ddos_type"])

        misp_event.add_object(new_object_2)

        if attrs["cnc_ip"] is not None:
            new_object_3 = MISPObject("C&C information")

            new_object_3.add_attribute("C&C", type="text", value=attrs["cnc"])
            send_ip = True if attrs["cnc_url"] is None else False
            new_object_3.add_attribute("C&C-IP", type="ip-src", value=attrs["cnc_ip"], to_ids=send_ip)
            new_object_3.add_attribute("C&C-IP-city", type="text", value=attrs["cnc_ip_city"])
            new_object_3.add_attribute("C&C-IP-country-code", type="text", value=attrs["cnc_ip_country_code"])
            new_object_3.add_attribute("C&C-IP-country-name", type="text", value=attrs["cnc_ip_country_name"])
            new_object_3.add_attribute("C&C-IP-region", type="text", value=attrs["cnc_ip_region"])
            new_object_3.add_attribute("C&C-IP-provider", type="text", value=attrs["cnc_ip_provider"])
            new_object_3.add_attribute("C&C-IP-asn", type="text", value=attrs["cnc_ip_asn"])
            new_object_3.add_attribute("C&C-domain", type="domain", value=attrs["cnc_domain"], to_ids=True)
            new_object_3.add_attribute("C&C-url", type="url", value=attrs["cnc_url"], to_ids=True)

            misp_event.add_object(new_object_3)

        return misp_event


    def domain_processor(self, event, feed):
        attrs = event["attrs"]
        if attrs["domain"] is None:
            return 0

        misp_event = MISPEvent()
        misp_event.add_attribute(type="text", value="Group-IB Threat Intelligence: " + info_dict[feed])
        misp_event.info = attrs["domain"]

        new_object_1 = MISPObject("Domain information")

        new_object_1.add_attribute("Domain", type="domain", value=attrs["domain"])
        new_object_1.add_attribute("Date-registered", type="datetime", value=attrs["date_registered"])
        new_object_1.add_attribute("Date-expired", type="datetime", value=attrs["date_expired"])
        new_object_1.add_attribute("Virus-total", type="text", value=attrs["detection_rate"])
        new_object_1.add_attribute("Owner", type="text", value=attrs["person"])
        new_object_1.add_attribute("Owner-address", type="text", value=attrs["address"])
        new_object_1.add_attribute("Owner-phone", type="phone-number", value=attrs["phone"])
        new_object_1.add_attribute("Owner-organization", type="text", value=attrs["organization"])
        new_object_1.add_attribute("Owner-registrar", type="text", value=attrs["registrar"])
        new_object_1.add_attribute("Abuse-e-mail", type="text", value=attrs["email"])
        new_object_1.add_attribute("Favicon-md5", type="text", value=attrs["favicon_md5"])
        new_object_1.add_attribute("Status", type="text", value=attrs["status"])
        new_object_1.add_attribute("Type", type="text", value=attrs["type"])

        misp_event.add_object(new_object_1)

        if len(attrs["name_server"]) > 0:
            new_object_2 = MISPObject("Server names")

            for name_server in attrs["name_server"]:
                new_object_2.add_attribute("Server-name", type="text", value=name_server)

            misp_event.add_object(new_object_2)

        if attrs["server_ip"] is not None:
            new_object_3 = MISPObject("Server information")

            new_object_3.add_attribute("Server-IP", type="ip-src", value=attrs["server_ip"])
            new_object_3.add_attribute("Server-IP-asn", type="text", value=attrs["server_ip_asn"])
            new_object_3.add_attribute("Server-IP-city", type="text", value=attrs["server_ip_city"])
            new_object_3.add_attribute("Server-IP-country_code", type="text", value=attrs["server_ip_country_code"])
            new_object_3.add_attribute("Server-IP-country-name", type="text", value=attrs["server_ip_country_name"])
            new_object_3.add_attribute("Server-IP-provider", type="text", value=attrs["server_ip_provider"])
            new_object_3.add_attribute("Server-IP-region", type="text", value=attrs["server_ip_region"])

            misp_event.add_object(new_object_3)

        if attrs["screenshot"] is not None or attrs["html"] is not None or attrs["favicon"] is not None:
            new_object_4 = MISPObject("Links")

            new_object_4.add_attribute("Screenshot", type="url", value=attrs["screenshot"])
            new_object_4.add_attribute("html", type="url", value=attrs["html"])
            new_object_4.add_attribute("favicon", type="url", value=attrs["favicon"])

            misp_event.add_object(new_object_4)

        return misp_event


    def ssl_processor(self, event, feed):
        attrs = event["attrs"]

        misp_event = MISPEvent()
        misp_event.add_attribute(type="text", value="Group-IB Threat Intelligence: " + info_dict[feed])
        misp_event.info = attrs["hash"] if attrs["hash"] is not None and attrs["hash"] != "" else "SSL info"

        new_object_1 = MISPObject("SSL information")

        new_object_1.add_attribute("Hash", type="sha1", value=attrs["hash"])
        new_object_1.add_attribute("Certificate-valid-to", type="datetime", value=attrs["date_not_before"])
        new_object_1.add_attribute("Certificate-valid-from", type="datetime", value=attrs["date_not_after"])
        new_object_1.add_attribute("Host-count", type="text", value=attrs["hosts_count"])
        new_object_1.add_attribute("Status", type="text", value=attrs["status"])
        new_object_1.add_attribute("Type", type="text", value=attrs["type"])
        new_object_1.add_attribute("Favicon-md5", type="text", value=attrs["favicon_md5"])

        misp_event.add_object(new_object_1)

        if attrs["subject_org"] is not None:
            new_object_2 = MISPObject("Subject information")

            new_object_2.add_attribute("Subject-organization", type="text", value=attrs["subject_org"])
            new_object_2.add_attribute("Subject-domain", type="text", value=attrs["subject_common"])
            new_object_2.add_attribute("Subject-country-code", type="text", value=attrs["subject_country_code"])
            new_object_2.add_attribute("Subject-location", type="text", value=attrs["subject_locality"])
            new_object_2.add_attribute("Subject-region", type="text", value=attrs["subject_region"])

            misp_event.add_object(new_object_2)

        if attrs["issuer_name"] is not None:
            new_object_3 = MISPObject("Issuer information")

            new_object_3.add_attribute("Issuer-name", type="text", value=attrs["issuer_name"])
            new_object_3.add_attribute("Issuer-organization", type="text", value=attrs["issuer_org"])
            new_object_3.add_attribute("Issuer-country-code", type="text", value=attrs["issuer_country_code"])

            misp_event.add_object(new_object_3)

        if attrs["domain_name"] is not None:
            new_object_4 = MISPObject("Domain information")

            new_object_4.add_attribute("Domain-name", type="domain", value=attrs["domain_name"])
            new_object_4.add_attribute("Domain-registered", type="datetime", value=attrs["domain_registered"])
            new_object_4.add_attribute("Domain-expired", type="datetime", value=attrs["domain_expired"])
            new_object_4.add_attribute("Domain-registrar", type="text", value=attrs["domain_registrar"])
            new_object_4.add_attribute("Domain-page-title", type="text", value=attrs["domain_page_title"])

            misp_event.add_object(new_object_4)

        if attrs["server_ip"] is not None:
            new_object_5 = MISPObject("Server information")

            new_object_5.add_attribute("Server-IP", type="ip-src", value=attrs["server_ip"])
            new_object_5.add_attribute("Server-IP-asn", type="text", value=attrs["server_ip_asn"])
            new_object_5.add_attribute("Server-IP-city", type="text", value=attrs["server_ip_city"])
            new_object_5.add_attribute("Server-IP-country-code", type="text", value=attrs["server_ip_country_code"])
            new_object_5.add_attribute("Server-IP-country-name", type="text", value=attrs["server_ip_country_name"])
            new_object_5.add_attribute("Server-IP-provider", type="text", value=attrs["server_ip_provider"])
            new_object_5.add_attribute("Server-IP-region", type="text", value=attrs["server_ip_region"])

            misp_event.add_object(new_object_5)

        if attrs["screenshot"] is not None or attrs["html"] is not None or attrs["favicon"] is not None:
            new_object_6 = MISPObject("Additional information")

            new_object_6.add_attribute("Screenshot", type="url", value=attrs["screenshot"])
            new_object_6.add_attribute("Html", type="url", value=attrs["html"])
            new_object_6.add_attribute("Favicon", type="url", value=attrs["favicon"])

            misp_event.add_object(new_object_6)

        return misp_event


    def phishing_processor(self, event, feed): # TODO: IP or URL?..
        attrs = event["attrs"]

        misp_event = MISPEvent()
        misp_event.add_attribute(type="text", value="Group-IB Threat Intelligence: " + info_dict[feed])
        misp_event.info = attrs["phishing_ip"] if attrs["phishing_ip"] is not None and attrs["phishing_ip"] != "" else "Phishing info"

        if attrs["date_detected"] is not None or attrs["date_blocked"] is not None:
            new_object_1 = MISPObject("Dates")

            new_object_1.add_attribute("Date-detected", type="datetime", value=attrs["date_detected"])
            new_object_1.add_attribute("Date-blocked", type="datetime", value=attrs["date_blocked"])

            misp_event.add_object(new_object_1)

        if attrs["target_brand"] is not None:
            new_object_2 = MISPObject("Target brand information")

            new_object_2.add_attribute("Target-brand", type="text", value=attrs["target_brand"])
            new_object_2.add_attribute("Target-country-name", type="text", value=attrs["target_country_name"])
            new_object_2.add_attribute("Target-category", type="text", value=attrs["target_category"])
            new_object_2.add_attribute("Target-domain", type="domain", value=attrs["target_domain"], to_ids=False)

            misp_event.add_object(new_object_2)

        if attrs["phishing_ip"] is not None:
            new_object_3 = MISPObject("Phishing IP information")

            send_ip = True if attrs["phishing_url"] is None else False
            new_object_3.add_attribute("Phishing-IP", type="ip-src", value=attrs["phishing_ip"], to_ids=send_ip)
            new_object_3.add_attribute("Phishing-IP-city", type="text", value=attrs["phishing_ip_city"])
            new_object_3.add_attribute("Phishing-IP-country-code", type="text", value=attrs["phishing_ip_country_code"])
            new_object_3.add_attribute("Phishing-IP-country-name", type="text", value=attrs["phishing_ip_country_name"])
            new_object_3.add_attribute("Phishing-IP-region", type="text", value=attrs["phishing_ip_region"])
            new_object_3.add_attribute("Phishing-IP-provider", type="text", value=attrs["phishing_ip_provider"])
            new_object_3.add_attribute("Phishing-IP-asn", type="text", value=attrs["phishing_ip_asn"])

            misp_event.add_object(new_object_3)

        if attrs["phishing_domain"] is not None:
            new_object_4 = MISPObject("Phishing domain information")

            new_object_4.add_attribute("Phishing-domain", type="domain", value=attrs["phishing_domain"])
            new_object_4.add_attribute("Phishing-domain-local", type="text", value=attrs["phishing_domain_local"])
            new_object_4.add_attribute("Phishing-domain-title", type="text", value=attrs["phishing_domain_title"])
            new_object_4.add_attribute("Phishing-domain-registered", type="datetime", value=attrs["phishing_domain_registered"])
            new_object_4.add_attribute("Phishing-domain-registrar", type="text", value=attrs["phishing_domain_registrar"])

            misp_event.add_object(new_object_4)

        if attrs["phishing_url"] is not None:
            new_object_5 = MISPObject("Phishing URL information")

            new_object_5.add_attribute("Phishing-URL", type="url", value=attrs["phishing_url"])
            new_object_5.add_attribute("Phishing-URL-title", type="text", value=attrs["phishing_url_title"])

            misp_event.add_object(new_object_5)

        if attrs["phishing_kit_id"] is not None:
            new_object_6 = MISPObject("Phishing kit information")

            new_object_6.add_attribute("Phishing-kit-id", type="text", value=attrs["phishing_kit_id"])
            new_object_6.add_attribute("Phishing-kit", type="text", value=attrs["phishing_kit"])
            new_object_6.add_attribute("Phishing-kit-email", type="text", value=attrs["phishing_kit_email"])
            new_object_6.add_attribute("Phishing-kit-signature", type="text", value=attrs["phishing_kit_signature"])
            new_object_6.add_attribute("Phishing-kit-signature_id", type="text", value=attrs["phishing_kit_signature_id"])

            misp_event.add_object(new_object_6)

        return misp_event


    def advert_processor(self, event, feed):
        attrs = event["attrs"]
        if attrs["advert_url"] is None:
            return 0

        misp_event = MISPEvent()
        misp_event.add_attribute(type="text", value="Group-IB Threat Intelligence: " + info_dict[feed])
        misp_event.info = attrs["advert_url"]

        new_object_1 = MISPObject("Advertising information")

        new_object_1.add_attribute("Date-detected", type="datetime", value=attrs["date_detected"])
        new_object_1.add_attribute("Advertising-URL", type="url", value=attrs["advert_url"])
        new_object_1.add_attribute("Advertising-Title", type="text", value=attrs["advert_title"])
        new_object_1.add_attribute("Advertising-icon-MD5", type="text", value=attrs["advert_icon_md5"])
        new_object_1.add_attribute("Status", type="text", value=attrs["status"])
        new_object_1.add_attribute("Type", type="text", value=attrs["type"])
        new_object_1.add_attribute("VirusTotal-detection-rate-detected", type="text", value=attrs["vt_detected"])
        new_object_1.add_attribute("VirusTotal-detection-rate-total", type="text", value=attrs["vt_all"])

        misp_event.add_object(new_object_1)

        if attrs["advert_domain"] is not None:
            new_object_2 = MISPObject("Advertising domain information")

            new_object_2.add_attribute("Advertising-domain", type="domain", value=attrs["advert_domain"])
            new_object_2.add_attribute("Advertising-domain-registrar", type="text", value=attrs["advert_domain_registrar"])
            new_object_2.add_attribute("Advertising-domain-registered", type="datetime", value=attrs["advert_domain_registered"])

            misp_event.add_object(new_object_2)

        if attrs["source_advert_url_puny"] is not None:
            new_object_3 = MISPObject("Source advertising information")

            new_object_3.add_attribute("Source-advertising-URL", type="url", value=attrs["source_advert_url_puny"])
            new_object_3.add_attribute("Source-advertising-title", type="text", value=attrs["source_advert_title"])
            new_object_3.add_attribute("Source-advertising-description", type="text", value=attrs["source_advert_description"])

            misp_event.add_object(new_object_3)

        if attrs["advert_ip"] is not None:
            new_object_4 = MISPObject("Advertising IP information")

            send_ip = True if attrs["advert_url"] is None else False
            new_object_4.add_attribute("Advertising-IP", type="ip-src", value=attrs["advert_ip"], to_ids=send_ip)
            new_object_4.add_attribute("Advertising-IP-provider", type="text", value=attrs["advert_ip_provider"])
            new_object_4.add_attribute("Advertising-IP-asn", type="text", value=attrs["advert_ip_asn"])
            new_object_4.add_attribute("Advertising-IP-city", type="text", value=attrs["advert_ip_city"])
            new_object_4.add_attribute("Advertising-IP-country-code", type="text", value=attrs["advert_ip_country_code"])
            new_object_4.add_attribute("Advertising-IP-country-name", type="text", value=attrs["advert_ip_country_name"])
            new_object_4.add_attribute("Advertising-IP-region", type="text", value=attrs["advert_ip_region"])

            misp_event.add_object(new_object_4)

        if attrs["client_ip"] is not None:
            new_object_5 = MISPObject("Client IP information")

            new_object_5.add_attribute("Client-IP", type="ip-dst", value=attrs["client_ip"])
            new_object_5.add_attribute("Client-IP-country", type="text", value=attrs["client_ip_country"])
            new_object_5.add_attribute("Client-IP-city", type="text", value=attrs["client_ip_city"])
            new_object_5.add_attribute("Client-IP-timezone", type="text", value=attrs["client_ip_timezone"])

            misp_event.add_object(new_object_5)

        return misp_event


    def mobileapp_processor(self, event, feed):
        attrs = event["attrs"]
        if attrs["name"] is None:
            return 0

        misp_event = MISPEvent()
        misp_event.add_attribute(type="text", value="Group-IB Threat Intelligence: " + info_dict[feed])
        misp_event.info = attrs["name"]

        new_object_1 = MISPObject("Mobile application information")

        new_object_1.add_attribute("Date-published", type="datetime", value=attrs["date_published"])
        new_object_1.add_attribute("Date-updated", type="datetime", value=attrs["date_updated"])
        new_object_1.add_attribute("Name", type="text", value=attrs["name"])
        new_object_1.add_attribute("Author", type="text", value=attrs["author"])
        new_object_1.add_attribute("Category", type="text", value=attrs["category"])
        new_object_1.add_attribute("Status", type="text", value=attrs["status"])
        new_object_1.add_attribute("Type", type="text", value=attrs["type"])
        new_object_1.add_attribute("Description", type="comment", value=attrs["description"])
        new_object_1.add_attribute("Download-count", type="text", value=attrs["download_count"])
        new_object_1.add_attribute("Size", type="text", value=attrs["size"])

        misp_event.add_object(new_object_1)

        if len(attrs["url"]) > 0:
            new_object_2 = MISPObject("URLs")

            for url in attrs["url"]:
                new_object_2.add_attribute("URL", type="url", value=url)

            misp_event.add_object(new_object_2)

        if len(attrs["md5"]) > 0:
            new_object_3 = MISPObject("Packet MD5")

            for md5 in attrs["md5"]:
                new_object_3.add_attribute("MD5 hash", type="md5", value=md5)

            misp_event.add_object(new_object_3)

        return misp_event


    def phishingkit_processor(self, event, feed):
        attrs = event["attrs"]
        if attrs["phishing_kit"] is None:
            return 0

        misp_event = MISPEvent()
        misp_event.add_attribute(type="text", value="Group-IB Threat Intelligence: " + info_dict[feed])
        misp_event.info = attrs["phishing_kit"]

        new_object_1 = MISPObject("Phishing kit information")

        new_object_1.add_attribute("Phishing-kit", type="text", value=attrs["phishing_kit"])
        new_object_1.add_attribute("Phishing-kit-file", type="filename", value=attrs["phishing_kit_file"])
        new_object_1.add_attribute("Phishing-kit-file-hash", type="sha256", value=attrs["phishing_kit_file_hash"])

        misp_event.add_object(new_object_1)

        if len(attrs["phishing_kit_email"]) > 0:
            new_object_2 = MISPObject("Phishing kit e-mail")

            for mail in attrs["phishing_kit_email"]:
                new_object_2.add_attribute("E-mail", type="email-src", value=mail)

            misp_event.add_object(new_object_2)

        if len(attrs["target_brand"]) > 0:
            new_object_3 = MISPObject("Target brand")

            for brand in attrs["target_brand"]:
                new_object_3.add_attribute("Brand", type="text", value=brand)

            misp_event.add_object(new_object_3)

        if len(attrs["phishing_kit_url"]) > 0:
            new_object_4 = MISPObject("URLs found in phishing kit")

            for url in attrs["phishing_kit_url"]:
                new_object_4.add_attribute("URL", type="url", value=url)

            misp_event.add_object(new_object_4)

        if len(attrs["phishing_kit_domain"]) > 0:
            new_object_5 = MISPObject("Domains found in phishing kit")

            for domain in attrs["phishing_kit_domain"]:
                new_object_5.add_attribute("Domain", type="domain", value=domain)

            misp_event.add_object(new_object_5)

        return misp_event


    def tornodes_processor(self, event, feed):
        attrs = event["attrs"]
        if attrs["tor_ip"] is None:
            return 0

        misp_event = MISPEvent()
        misp_event.add_attribute(type="text", value="Group-IB Threat Intelligence: " + info_dict[feed])
        misp_event.info = attrs["tor_ip"]

        if attrs["date_detected"] is not None or attrs["date_first_seen"] is not None:
            new_object_1 = MISPObject("Dates")

            new_object_1.add_attribute("Date-detected", type="datetime", value=attrs["date_detected"])
            new_object_1.add_attribute("Date-first-seen", type="datetime", value=attrs["date_first_seen"])

            misp_event.add_object(new_object_1)

        new_object_2 = MISPObject("TOR node information")

        new_object_2.add_attribute("TOR-IP", type="ip-src", value=attrs["tor_ip"])
        new_object_2.add_attribute("TOR-IP-asn", type="text", value=attrs["tor_ip_asn"])
        new_object_2.add_attribute("TOR-IP-city", type="text", value=attrs["tor_ip_city"])
        new_object_2.add_attribute("TOR-IP-country-code", type="text", value=attrs["tor_ip_country_code"])
        new_object_2.add_attribute("TOR-IP-country-name", type="text", value=attrs["tor_ip_country_name"])
        new_object_2.add_attribute("TOR-IP-provider", type="text", value=attrs["tor_ip_provider"])
        new_object_2.add_attribute("TOR-IP-region", type="text", value=attrs["tor_ip_region"])
        new_object_2.add_attribute("Source", type="text", value=attrs["source"])

        misp_event.add_object(new_object_2)

        return misp_event


    def proxy_processor(self, event, feed):
        attrs = event["attrs"]
        if attrs["proxy_ip"] is None:
            return 0

        misp_event = MISPEvent()
        misp_event.add_attribute(type="text", value="Group-IB Threat Intelligence: " + info_dict[feed])
        misp_event.info = attrs["proxy_ip"]

        if attrs["date_detected"] is not None or attrs["date_first_seen"] is not None:
            new_object_1 = MISPObject("Dates")

            new_object_1.add_attribute("Date-detected", type="datetime", value=attrs["date_detected"])
            new_object_1.add_attribute("Date-first-seen", type="datetime", value=attrs["date_first_seen"])

            misp_event.add_object(new_object_1)

        new_object_2 = MISPObject("Open Proxy server information")

        new_object_2.add_attribute("Proxy-IP", type="ip-src", value=attrs["proxy_ip"])
        new_object_2.add_attribute("Proxy-IP-asn", type="text", value=attrs["proxy_ip_asn"])
        new_object_2.add_attribute("Proxy-IP-city", type="text", value=attrs["proxy_ip_city"])
        new_object_2.add_attribute("Proxy-IP-country-code", type="text", value=attrs["proxy_ip_country_code"])
        new_object_2.add_attribute("Proxy-IP-country-name", type="text", value=attrs["proxy_ip_country_name"])
        new_object_2.add_attribute("Proxy-IP-provider", type="text", value=attrs["proxy_ip_provider"])
        new_object_2.add_attribute("Proxy-IP-region", type="text", value=attrs["proxy_ip_region"])
        new_object_2.add_attribute("Proxy-port", type="port", value=attrs["proxy_port"])
        new_object_2.add_attribute("Proxy-type-protocol", type="text", value=attrs["type"])
        new_object_2.add_attribute("Proxy-type", type="text", value=attrs["anonymous"])
        new_object_2.add_attribute("Source", type="text", value=attrs["source"])

        misp_event.add_object(new_object_2)

        return misp_event


    def socks_processor(self, event, feed):
        attrs = event["attrs"]
        if attrs["socks_ip"] is None:
            return 0

        misp_event = MISPEvent()
        misp_event.add_attribute(type="text", value="Group-IB Threat Intelligence: " + info_dict[feed])
        misp_event.info = attrs["socks_ip"]

        if attrs["date_detected"] is not None or attrs["date_first_seen"] is not None:
            new_object_1 = MISPObject("Dates")

            new_object_1.add_attribute("Date-detected", type="datetime", value=attrs["date_detected"])
            new_object_1.add_attribute("Date-first-seen", type="datetime", value=attrs["date_first_seen"])

            misp_event.add_object(new_object_1)

        new_object_2 = MISPObject("Private/Botnet SOCKS information")

        new_object_2.add_attribute("SOCKS-IP", type="ip-src", value=attrs["socks_ip"])
        new_object_2.add_attribute("SOCKS-IP-asn", type="text", value=attrs["socks_ip_asn"])
        new_object_2.add_attribute("SOCKS-IP-city", type="text", value=attrs["socks_ip_city"])
        new_object_2.add_attribute("SOCKS-IP-country-code", type="text", value=attrs["socks_ip_country_code"])
        new_object_2.add_attribute("SOCKS-IP-country-name", type="text", value=attrs["socks_ip_country_name"])
        new_object_2.add_attribute("SOCKS-IP-provider", type="text", value=attrs["socks_ip_provider"])
        new_object_2.add_attribute("SOCKS-IP-region", type="text", value=attrs["socks_ip_region"])
        new_object_2.add_attribute("SOCKS-port", type="port", value=attrs["socks_port"])
        new_object_2.add_attribute("SOCKS-type-protocol", type="text", value=attrs["type"])
        new_object_2.add_attribute("SOCKS-type", type="text", value=attrs["anonymous"])
        new_object_2.add_attribute("Source", type="text", value=attrs["source"])

        misp_event.add_object(new_object_2)

        return misp_event


    def leaks_processor(self, event, feed):
        attrs = event["attrs"]
        if attrs["title"] is None:
            return 0

        misp_event = MISPEvent()
        misp_event.add_attribute(type="text", value="Group-IB Threat Intelligence: " + info_dict[feed])
        misp_event.info = attrs["title"]

        new_object_1 = MISPObject("Leak information")

        new_object_1.add_attribute("Title", type="text", value=attrs["title"])
        new_object_1.add_attribute("Date-detected", type="datetime", value=attrs["date_detected"])
        new_object_1.add_attribute("Date-published", type="datetime", value=attrs["date_publish"])
        new_object_1.add_attribute("Date-expire", type="datetime", value=attrs["date_expire"])
        new_object_1.add_attribute("Source", type="text", value=attrs["source"])
        new_object_1.add_attribute("Author", type="text", value=attrs["author"])
        new_object_1.add_attribute("Language", type="text", value=attrs["language"])
        new_object_1.add_attribute("Size", type="text", value=attrs["size"])
        new_object_1.add_attribute("Status", type="text", value=attrs["status"])
        new_object_1.add_attribute("Link", type="url", value=attrs["link"])
        new_object_1.add_attribute("Internal-link", type="url", value=attrs["internal_link"], to_ids=False)

        misp_event.add_object(new_object_1)

        return misp_event


    def hacktivism_processor(self, event, feed):
        attrs = event["attrs"]

        misp_event = MISPEvent()
        misp_event.add_attribute(type="text", value="Group-IB Threat Intelligence: " + info_dict[feed])
        misp_event.info = attrs["operation_name"]

        new_object_1 = MISPObject("Hacktivism operation information")

        new_object_1.add_attribute("Operaion-name", type="text", value=attrs["operation_name"])
        new_object_1.add_attribute("Operation-date", type="datetime", value=attrs["operation_date"])
        if len(attrs["attack_type"]) > 0:
            new_object_1.add_attribute("Attack-type", type="text", value=', '.join(attrs["attack_type"]))
        new_object_1.add_attribute("Attack-result", type="text", value=attrs["attack_result"])
        new_object_1.add_attribute("Team", type="text", value=attrs["team"])
        if len(attrs["target_category"]) > 0:
            new_object_1.add_attribute("Target-category", type="text", value=', '.join(attrs["target_category"]))
        if len(attrs["target_country_name"]) > 0:
            new_object_1.add_attribute("Target-country-name", type="text", value=', '.join(attrs["target_country_name"]))

        misp_event.add_object(new_object_1)

        if len(attrs["message_link"]) > 0:
            new_object_2 = MISPObject("Message links")

            for link in attrs["message_link"]:
                new_object_2.add_attribute("Message-link", type="url", value=link, to_ids=False)

            misp_event.add_object(new_object_2)

        if len(attrs["target_urls"]) > 0:
            new_object_3 = MISPObject("Target URLs")

            for url in attrs["target_urls"]:
                new_object_3.add_attribute("URL", type="url", value=url, to_ids=False)

            misp_event.add_object(new_object_3)

        if len(attrs["evidence_link"]) > 0:
            new_object_4 = MISPObject("Evidence links")

            for link in attrs["evidence_link"]:
                new_object_4.add_attribute("Evidence-link", type="url", value=link, to_ids=False)

            misp_event.add_object(new_object_4)

        return misp_event


    def sample_processor(self, event, feed):
        attrs = event["attrs"]
        if attrs["name"] is None:
            return 0

        misp_event = MISPEvent()
        misp_event.add_attribute(type="text", value="Group-IB Threat Intelligence: " + info_dict[feed])
        misp_event.info = attrs["name"]

        new_object_1 = MISPObject("Targeted malware information")

        new_object_1.add_attribute("Name", type="text", value=attrs["name"])
        new_object_1.add_attribute("Date", type="datetime", value=attrs["date"])
        new_object_1.add_attribute("MD5", type="md5", value=attrs["md5"])
        new_object_1.add_attribute("Size", type="text", value=attrs["size"])
        new_object_1.add_attribute("Criminal-group-name", type="text", value=attrs["cybercrime"])
        new_object_1.add_attribute("File-name", type="filename", value=attrs["file_name"])
        new_object_1.add_attribute("File-type", type="text", value=attrs["file_type"])
        new_object_1.add_attribute("File-version", type="text", value=attrs["file_version"])
        new_object_1.add_attribute("Inject-MD5", type="md5", value=attrs["inject_md5"])
        new_object_1.add_attribute("Inject-dump", type="text", value=attrs["inject_dump"])
        new_object_1.add_attribute("Platform", type="text", value=attrs["platform"])

        misp_event.add_object(new_object_1)

        if len(attrs["cnc_addr"]) > 0:
            new_object_2 = MISPObject("C&C addresses")

            for elem in attrs["cnc_addr"]:
                elem_type = "ip-src" if self.valid_ip(elem) else "url"
                new_object_2.add_attribute("C&C-address", type=elem_type, value=elem)

            misp_event.add_object(new_object_2)

        if len(attrs["cnc_ip"]) > 0:
            new_object_3 = MISPObject("C&C IPs")

            for elem in attrs["cnc_ip"]:
                new_object_3.add_attribute("C&C-IP", type="ip-src", value=elem)

            misp_event.add_object(new_object_3)

        if len(attrs["cnc_ip_country_name"]) > 0:
            new_object_4 = MISPObject("C&C country names")

            for elem in attrs["cnc_ip_country_name"]:
                new_object_4.add_attribute("C&C-country-name", type="text", value=elem)

            misp_event.add_object(new_object_4)

        return misp_event


    def threats_processor(self, event, feed):
        attrs = event["attrs"]
        if attrs["threat_name"] is None:
            return 0

        misp_event = MISPEvent()
        misp_event.add_attribute(type="text", value="Group-IB Threat Intelligence: " + info_dict[feed])
        misp_event.info = attrs["threat_name"]

        new_object_1 = MISPObject("Threat infromation")

        new_object_1.add_attribute("Name", type="text", value=attrs["threat_name"])
        new_object_1.add_attribute("Short-name", type="text", value=attrs["threat_short_name"])
        new_object_1.add_attribute("Date-reported", type="datetime", value=attrs["date_report"])
        new_object_1.add_attribute("Date-detected", type="datetime", value=attrs["date_detected"])
        new_object_1.add_attribute("Description", type="comment", value=attrs["threat_descr"])
        new_object_1.add_attribute("Full-description-link", type="url", value=attrs["link"], to_ids=False)

        misp_event.add_object(new_object_1)

        new_objects = {
            "cnc": MISPObject("C&C servers"),
            "domain": MISPObject("Domains"),
            "ip": MISPObject("IP list"),
            "file": MISPObject("Files"),
            "file_hash": MISPObject("File hashes"),
            "url": MISPObject("URL list"),
            "anonymization": MISPObject("Anonymization"),
            "email": MISPObject("E-mail list")
        }

        hashes = {
            32: "md5",
            40: "sha1",
            64: "sha256"
        }

        for ind in attrs["indicators"]:
            for val in ind["value"]:
                if ind["type"] in new_objects.keys():
                    attribute_name = ind["type"][0].upper() + ind["type"][1:]

                    if ind["type"] in [ "cnc", "ip", "anonymization" ]:
                        attribute_type = "ip-src"
                    elif ind["type"] in [ "url", "domain" ]:
                        attribute_type = ind["type"]
                    elif ind["type"] == "file":
                        attribute_type = "filename"

                        if ind["params"] != []:
                            for key_p, val_p in ind["params"].items():
                                if key_p == "hash_md5":
                                    new_objects["file_hash"].add_attribute("File_hash", type="md5", value=val_p)
                                elif key_p == "hash_sha_1":
                                    new_objects["file_hash"].add_attribute("File_hash", type="sha1", value=val_p)
                                elif key_p == "hash_sha_256":
                                    new_objects["file_hash"].add_attribute("File_hash", type="sha256", value=val_p)

                    elif ind["type"] == "file_hash":
                        try:
                            attribute_type = hashes[len(val)]
                        except KeyError:
                            print("KeyError: strange hash " + str(val) + " at threat ID " + str(event["id"]))
                            continue
                    else:
                        attribute_type = "email-src"

                    new_objects[ind["type"]].add_attribute(attribute_name, type=attribute_type, value=val)

        for obj in new_objects.values():
            if "Attribute" in obj.to_dict().keys():
                misp_event.add_object(obj)

        return misp_event
