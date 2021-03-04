import subprocess


def directory_brute_force(url):
    directory_found = []
    # urlInput = input("please insert url: ")
    direct = subprocess.check_output('C:/Users/orian.cohen/Desktop/securityToolsAuth/gobuster.exe dir -u' + url + '-t 300 --wildcard -w /Users/orian.cohen/Desktop/securityToolsAuth/Web-Content/seclist-directory.txt -l -v')

    for line in direct.split(b'\n'):
        result = "".join(chr(x) for x in line)
        if 'Found' in result:
            print(result)
            directory_found.append(result)

    return directory_found


def files_brute_force(url):
    directory_found = []
    direct2 = subprocess.check_output('C:/Users/orian.cohen/Desktop/securityToolsAuth/gobuster.exe dir -u' + url + '-t 300 --wildcard -w /Users/orian.cohen/Desktop/securityToolsAuth/Web-Content/seclist-directory.txt -x .php,.html')

    for line in direct2.split(b'\n'):
        result = "".join(chr(x) for x in line)
        if 'Found' in result:
            print(result)
            directory_found.append(result)

    for line in direct2.split(b'\n'):
        directory_found.append(line)

    return directory_found



