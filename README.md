This repository contains **Virus Definitions** for the **[ScanCore](https://github.com/zelon88/ScanCore) Virus Scanner**.

## About Viruses


It may seem obvious, but it is important to describe what a **Virus** means in the context of a Virus Scanner.
For the purpose of this document, a "Virus" is considered to be a piece of computer code or software which causes unauthorized or unintended behaviour without the consent or approval of the owner or operator of the device.
This definition encompasses what is commonly referred to as **Viruses**, (including _Trojans_, _Ransomware_, or _Worms_) **Malware** (including _Keyloggers_, _Botnets_ or _Trackers_) & **Potentially Unwanted Programs (PUPs)** (including _Remote Access Tools_, _Adware_, or _Auto-Miners_). 

## About Virus Definitions

**Virus Definitions** are descriptive data artifacts that the ScanCore Virus Scanner uses to identify specific strains of infection during scanning operations.
Definitions within this repository are contained within **Definition Files**.

## About Definition Files

**Definition Files** are simple tab-separated files (TSV) with the _.def_ file extension.
These files can be opened by any plain text editor to reveal their contents.
The Definition Files contained within this repository all have the filename prefix _ScanCore__ & the file extension _.def_, but that is just to make things visually appealing.
ScanCore will accept Definitions Files with any filename prefix or file extension so long as the contents of the file are formatted properly.
Definition Files contain individual **Virus Definitions** organized into lines.
Each line is similar to a row in a spreadsheet, with each row representing a different strain of infection.
Each row is organized into columns which are separated by the tab character.
Each column represents a different piece of information about the infection in the corresponding row.
The columns contained within a row are ordered as follows;

1. Infection Name
2. Raw Data Match
3. MD5 Hash
4. SHA1 Hash
5. SHA256 Hash

If a piece of data is not available for a strain of infection, that column can be left blank.
If there are no more columns of a row that contain any data, the remaining columns of the row can be omitted.
Definition Files themselves within this repository are organized into **Definition Subscriptions** represented in the filename after the _ScanCore__ prefix, before the _.def_ file extension.

## About Definition Subscriptions


ScanCore client installations can subscribe to specific **Definition Subscriptions**.
Each definition file in this repository contains a different Definition Subscription.
Definition Subscriptions currently represent the major different types of infection, including;

1. Viruses
2. Malware
3. Potentially Unwanted Programs (PUPs)

In the future the list of subscriptions may expand to include geographic locations, industries, or more specific strains of infection.
Only the Definition Files that a ScanCore client has in it's Definition Subscriptions will be installed during **Definition Updates**.

## About Definition Updates

When a ScanCore client performs **Definition Updates**, it connects to a Git repository to download any Definition Files that match the local list of Definition Subscriptions.
Definition Updates can be performed using one of two methods, including;

1. Raw - Tries to download Definitions Files using _url_fopen_ first, then tries again if needed using cURL.
2. Git - Tries to download Definitions Files using Git.

Once Definition Files have been downloaded the ScanCore client compiles all Definition Files into a single local file known as the _Combined Definitions File_.
A _Combined Definitions File_ contains the contents of every Definition File that appears in the list of Definition Subscriptions for that client.
Everything about Definition Updates can be adjusted in the _ScanCore_Config.php_ file present in all default ScanCore installations.
Administrators can specify their own source for Definition Updates as well as specific subscriptions for precise, granular control over their environment.

<3 Open-Source
