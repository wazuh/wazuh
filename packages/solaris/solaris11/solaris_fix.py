import json
import argparse

aux_file_name = 'wazuh-agent.p5m.1.aux'

def clean_file(p5m1_file_path):
    aux_file = open(aux_file_name, 'w')
    with open(p5m1_file_path) as f:
        new_line = ""
        for line in f:
            if line[-2] == "\\":
                new_line += line[:-2]
            else:
                final_line = new_line + line
                aux_file.write(" ".join(final_line.split())+"\n")
                new_line = ""

    aux_file.close()

def set_p5m1(template_path, p5m1_file_path):

    # open template_agent_version.json file
    with open(template_path) as template_json:
        template = json.load(template_json)

    # open the p5m1 file for solaris 11 package
    with open(aux_file_name) as p5m1_file:
        pm51 = p5m1_file.readlines()

    new_file = aux_file_name+".fixed"

    with open(new_file, "w") as p5m1_fixed:
        p5m1_fixed.write("dir  path=var/ossec owner=root group=wazuh mode=0750"+"\n")
        for line in pm51:
            line_components = line.split(' ')
            # if the element is a directory or a file, set the necessary
            if line_components[0] != "link":
                if line_components[0] == "file":
                    file_path = 'var/ossec/' + line_components[2].split('=')[1]
                    if aux_file_path in template:
                        # get the properties of the file from the agent template
                        file_properties = template[aux_file_path]
                        # set the path
                        line_components[2] = 'path=' + file_path
                        # set the owner
                        line_components[3] = 'owner=' + file_properties['user']
                        # set the group
                        line_components[4] = 'group=' + file_properties['group']
                        # set the permissions
                        line_components[5] = 'mode=' + file_properties['mode']
                        # write the line into the file
                        p5m1_fixed.write("".join([i + " " for i in line_components])+"\n")

                elif line_components[0] == "dir":
                    file_path = 'var/ossec/' + line_components[1].split('=')[1]
                    aux_file_path = '/' + file_path
                    if aux_file_path in template:
                        # get the properties of the file from the agent template
                        file_properties = template[aux_file_path]
                        # set the path
                        line_components[1] = 'path=' + file_path
                        # set the owner
                        line_components[2] = 'owner=' + file_properties['user']
                        # set the group
                        line_components[3] = 'group=' + file_properties['group']
                        # set the permissions
                        line_components[4] = 'mode=' + file_properties['mode']
                        # write the line into the file
                        p5m1_fixed.write("".join([i + " " for i in line_components])+"\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--template_path", type=str, help="Path where the wazuh_agent_vVERSION is located.", required=True)
    parser.add_argument("-p", "--p5m1_file_path", type=str, help="Path where the wazuh-agent.p5m.1 file is located.", required=True)
    args = parser.parse_args()

    clean_file(p5m1_file_path=args.p5m1_file_path)
    set_p5m1(template_path=args.template_path, p5m1_file_path=args.p5m1_file_path)

if __name__ == "__main__":
    main()
