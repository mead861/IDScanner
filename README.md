# IDScanner
This plugin will scan for user IDs

I wrote this Burpsuite plugin to look for user id paterns. This plugin supports active and passive scanning. This plugin does not work with out editing the regex. Look for the comment in idscanner.py.


 # change prefix to match user id format
	   
        regex = "[*prefix*]"
        issuename = "User ID Found"
        issuelevel = "Medium"
        issuedetail = """The application response contains a User ID
                <br><br><b>$ID$</b><br><br>  """
