# NauthNRPC

## Description

NauthNRPC is a Python tool that introduces a new method for gathering domain information, including the enumeration of domain users. The tool leverages auth-level = 1 (No authentication) against the MS-NRPC (Netlogon) interface on domain controllers. All that's required is the domain controller's IP address, and the entire process can be completed without providing any credentials.

Preventing such enumeration is challenging, and detection poses difficulties for blue teamers. For further details, please refer to my [research](https://securelist.com/no-auth-domain-information-enumeration/112629/)


## Key Features


- **Domain Information Enumeration:** The tool extracts information such as the DC name, domain name, domain GUID, site name, forest name, and various flags that indicate properties of the DC.

- **Trusted Domains:** The tool extracts information related to the domain's trusted domains and provides details about the trusted relationships.

- **Users and Computers Enumeration:** The tool can enumerate domain users and computers and check for their existence

## Compatibility
This tool has been tested with Windows servers 2012, 2016, 2019 and 2022.

## Usage

The tool requires Impacket to be installed beforehand. To execute the tool for domain information enumeration, you only need to specify the target using the "-t" flag:

```python3 nauth.py -t ip_address```

For enumerateing users or computers, you can provide a text file containing user/computer names, each separated by a new line:

```python3 nauth.py -t target -u users_file.txt -f computers_file.txt```

## Authors
Haidar kabibo, Kaspersky Security Services. Twitter: https://twitter.com/haider_kabibo 

## License
This software is provided under MIT Software License
