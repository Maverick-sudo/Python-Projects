#!/usr/bin/env python
import requests

def download(url):
    get_response = requests.get(url)
    filename = url.split("/")[-1]

    # By accessing url.split("/"), we obtain all the parts of the URL as separate elements in a list. The [-1] index is used to retrieve the last element of the list, which corresponds to the file name.
    # Open a file named based on the download name in write binary mode ('wb') The 'with' statement ensures that the file is properly closed after use

    with open(filename, 'wb') as out_file:
    # Write the content of the variable 'get_response.content' to the file
        out_file.write(get_response.content)


download("insert absolute download link")


