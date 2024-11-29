'''This iwll be the main file to converge all other files 
for threat detection and analysis'''

from file_scanner import check_file, load_config, get_file

if __name__ == "__main__":
    client = load_config()
    file_path = get_file()
    if file_path:
        check_file(client, file_path)
    else:
        print("Bruh you gotta select a file")

    client.close()
