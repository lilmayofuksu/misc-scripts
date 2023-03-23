import os, io
import sys
import re
import json

ua_file_handle: io.BufferedReader = None

def get_field_number(ua_path: str, cag_offset: int) -> int:
    ua_file_handle.seek(cag_offset)

    search_window = f.read(100)

    # lea edx, [r8+?]
    # or "41 8D 50 ?"

    pattern = b'\x41\x8D\x50'

    match = re.search(pattern, search_window)

    if match is None:
        return -1

    offset = match.start()

    # Get the field number
    field_number = search_window[offset + 3]

    return field_number


def dump_message_class(class_contents: str, protos: dict, base_type: str = "") -> None:
    class_name = class_contents.split("public class ")[1].split(" :")[0]

    property_start_offset = class_contents.find("\t// Properties")
    property_end_offset = class_contents.find("\t// Methods")

    if not base_type:
        if class_name not in protos:
            protos[class_name] = {"type": "message", "fields": []}
    else:
        if "messages" not in protos[base_type]:
            protos[base_type]["messages"] = {}
        
        if class_name not in protos[base_type]["messages"]:
            protos[base_type]["messages"][class_name] = {"fields": []}

    if property_start_offset == -1:
        print(f"Class {class_name} does not have properties")
        return

    # Get the properties
    property_content = class_contents[property_start_offset:property_end_offset].split("\n")
    property_content.pop(0)
    property_content.pop(len(property_content) - 1)
    property_content.pop(len(property_content) - 1)

    current_field_attribute = ""
    is_next_prop_browsable = False
    for propline in property_content:
        if propline.startswith("\t["):
            # Get the attribute name
            attribute_name = propline.split("[")[1].split("]")[0]
            if attribute_name == "ProtoMemberAttribute":
                current_field_attribute = propline
            elif attribute_name == "BrowsableAttribute":
                is_next_prop_browsable = True
        else:
            if "Specified { get; set; }" in propline or is_next_prop_browsable:
                is_next_prop_browsable = False
                continue

            #\t(\[([a-zA-Z]+)\]) \/\/ RVA: (0x[A-Z0-9]+) Offset: (0x[A-Z0-9]+) VA: (0x[A-Z0-9]+)\n
            prop_field_attribute = current_field_attribute
            current_field_attribute = ""

            prop_attribute_offset_re = re.match(r"\t(\[([a-zA-Z]+)\]) \/\/ RVA: (0x[A-Z0-9]+) Offset: (0x[A-Z0-9]+) VA: (0x[A-Z0-9]+)", prop_field_attribute)
            prop_field_offset_dict = {"rva": prop_attribute_offset_re.group(3), "offset": prop_attribute_offset_re.group(4), "va": prop_attribute_offset_re.group(5)}

            items = propline.split(" ")

            # Get property type & name
            prop_type, prop_name = items[1], items[2]

            # Get the field number
            field_number = get_field_number(sys.argv[2], int(prop_field_offset_dict["offset"], 16))

            # Print the result
            print(f"{class_name}.{prop_name} ({prop_type}) = {field_number}")

            is_nullable = f"{prop_name}Specified {{ get; set; }}" in class_contents

            field_obj = {"name": prop_name, "type": prop_type, "field_number": field_number}

            if is_nullable:
                field_obj["is_optional"] = True

            # Add the field to the proto
            if not base_type:
                protos[class_name]["fields"].append(field_obj)
            else:
                protos[base_type]["messages"][class_name]["fields"].append(field_obj)

def dump_enum_class(class_contents: str, protos: dict, base_type: str = "") -> None:
    enum_name = class_contents.split("public enum ")[1].split(" //")[0]
    lines = class_contents.split("\n")
    for line in lines:
        if line.startswith("\tpublic const"):
            enum_value = line.split(" = ")[0].strip().split(" ")[-1]
            enum_value_number = line.split(" = ")[1].strip().replace(";", "")
            print(f"{enum_name}.{enum_value} = {enum_value_number}")

            if not base_type:
                if enum_name not in protos:
                    protos[enum_name] = {"type": "enum", "values": []}

                protos[enum_name]["values"].append({"name": enum_value, "value": enum_value_number})
            else:
                if "enums" not in protos[base_type]:
                    protos[base_type]["enums"] = {}

                if enum_name not in protos[base_type]["enums"]:
                    protos[base_type]["enums"][enum_name] = {"values": []}

                protos[base_type]["enums"][enum_name]["values"].append({"name": enum_value, "value": enum_value_number})

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python main.py <path to dump.cs> <path to UserAssembly.dll>")
        sys.exit(1)

    if not os.path.exists(sys.argv[1]):
        print("dump.cs does not exist")
        sys.exit(1)

    if not os.path.exists(sys.argv[2]):
        print("(User/Game)Assembly.dll does not exist")
        sys.exit(1)

    protos = {}

    try:
        ua_file_handle = open(sys.argv[2], "rb")

        # Open the file and read the contents
        with open(sys.argv[1], "r", encoding="utf-8") as f:
            contents = f.read()

            # Match all lines that contain // Namespace: proto and make it into a list with offset
            proto_types = [(m.start(0), m.group(0)) for m in re.finditer(r"// Namespace: proto", contents)]

            # Parse the C# class
            for offset, line in proto_types:
                # Example class:
                # // Namespace: proto
                # [ProtoContractAttribute] // RVA: 0x509D40 Offset: 0x509140 VA: 0x180509D40
                # [Serializable]
                # public class AvatarSubSkill : IExtensible // TypeDefIndex: 3041

                # Get the class contents
                class_contents = contents[offset:contents.find("}\n\n//", offset) + 2]

                # Get the class name
                if "public class" not in class_contents:
                    if "public enum" in class_contents:
                        dump_enum_class(class_contents, protos)
                    else:
                        ...
                else:
                    dump_message_class(class_contents, protos)

                #Get class nested types
                if "public class" in class_contents:
                    class_name = class_contents.split("public class ")[1].split(" :")[0]

                    #Enums
                    class_nested_enums = [(m.start(0), m.group(0)) for m in re.finditer(rf"public enum {class_name}\.([a-zA-Z]+)", contents)]

                    for enum_offset, enum_line in class_nested_enums:
                        enum_contents = contents[enum_offset:contents.find("}\n\n//", enum_offset) + 2]
                        dump_enum_class(enum_contents, protos, class_name)      

                    #Nested classes/protos/types
                    class_nested_classes = [(m.start(0), m.group(0)) for m in re.finditer(rf"public class {class_name}\.([a-zA-Z]+)", contents)]

                    for class_offset, class_line in class_nested_classes:
                        subclass_contents = contents[class_offset:contents.find("}\n\n//", class_offset) + 2]
                        dump_message_class(subclass_contents, protos, class_name)

        # Write the protos to a json file
        with open("protos.json", "w") as f:
            print("Dumping completed, writing...")
            json.dump(protos, f, indent=4)

    finally:
        ua_file_handle.close()
    
    print("Done!")
