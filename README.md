# Asset Inventory***

A script to inventory all club assets and update asset Mongo database and SnipeIT via API.

# Install

`$ git clone https://github.com/rosieroberts/Inventory.git`

# Usage:

>To run script:
>`$ python3 inventory.py`

>No arguments - default scan all locations 

>Optional positional arguments: 
>-c, --club (club number) scans specific club/s  
>`$ python3 inventory.py -c club000` 
> 
>-d, debug mode (more detailed scanning info)
>`$ python3 inventory.py -d -c club000`

# Testing

Automated tests are included using the pytest framework. 
`$ python3 -m pytest`

# Documentation

See DOCS.md for more detailed documentation (in work)

