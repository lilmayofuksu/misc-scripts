import os, sys
import json

type_dict = {
    "int": "int32",
    "uint": "uint32",
    "long": "int64",
    "ulong": "uint64",
    "bool": "bool",
    "string": "string",
    "byte[]": "bytes",
    "double": "double",
    "float": "float"
}

def format_type(type: dict, skip_dot_split: bool = False):
    code = ""
    if "is_optional" in type and type["is_optional"] == True:
        code += "optional "
    elif "List<" not in type["type"]:
        code += "required "

    if type["type"] in type_dict:
        code += type_dict[type["type"]]
    else:
        if "List<" in type["type"]:
            code += "repeated "
            typename = type["type"].split("<")[1].split(">")[0]

            if not skip_dot_split:
                if "." in typename:
                    typename = typename.split(".")[-1]

            if typename in type_dict:
                code += type_dict[typename]
            else:
                code += typename

        elif "." in type["type"] and not skip_dot_split:
            code += type["type"].split(".")[1]
        else:
            code += type["type"]

    return code

def resolve_generic_type(type: str):
    if "<" in type:
        return type.split("<")[1].split(">")[0]
    else:
        return type

def insert_str(string, str_to_insert, index):
    return string[:index] + str_to_insert + string[index:]

def try_get_dict(obj, key):
    if key in obj:
        return obj[key]
    else:
        return {}

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python protogenerator.py <path to protos.json> <output_folder>")
        sys.exit(1)

    if not os.path.exists(sys.argv[1]):
        print("protos.json does not exist")
        sys.exit(1)

    if not os.path.exists(sys.argv[2]):
        os.makedirs(sys.argv[2])

    with open(sys.argv[1], "r") as f:
        protos: dict = json.load(f)

    for name, proto in protos.items():
        code = "syntax = \"proto2\";\n\n"

        if proto["type"] == "message":
            code += f"message {name} {{\n"

            if "fields" in proto:
                for field in proto["fields"]:
                    ball = False

                    if resolve_generic_type(field["type"]) not in type_dict:
                        if resolve_generic_type(field["type"]) not in try_get_dict(proto, "enums") and resolve_generic_type(field["type"]) not in try_get_dict(proto, "messages"):
                            import_line = f"import \"{resolve_generic_type(field['type']).split('.')[0]}.proto\";\n"

                            if import_line not in code:
                                code = insert_str(code, import_line, len("syntax = \"proto3\";\n\n"))

                            ball = True

                    field_type = format_type(field, ball)
                    code += f'    {field_type} {field["name"]} = {field["field_number"]};\n'

            if "enums" in proto:
                code += "\n"
                for enum_name, enum in proto["enums"].items():
                    enum_name_2 = enum_name.split(".")[1]
                    code += f'    enum {enum_name_2} {{\n'

                    #if enum_name_2 == "Retcode" or enum_name_2 == "CmdId":
                        #code += f'        option allow_alias = true;\n'                        

                    for value in enum["values"]:
                        code += f'        {value["name"]} = {value["value"]};\n'
                    code += "    }\n"

            if "messages" in proto:
                for message_name, message in proto["messages"].items():
                    code += f'    message {message_name.split(".")[1]} {{\n'

                    for field in message["fields"]:
                        ball = False

                        if resolve_generic_type(field["type"]) not in type_dict:
                            if resolve_generic_type(field["type"]) not in try_get_dict(proto, "enums") and resolve_generic_type(field["type"]) not in try_get_dict(proto, "messages"):
                                import_line = f"import \"{resolve_generic_type(field['type']).split('.')[0]}.proto\";\n"

                                if import_line not in code:
                                    code = insert_str(code, import_line, len("syntax = \"proto3\";\n\n"))

                                ball = True

                        field_type = format_type(field, ball)
                        code += f'        {field_type} {field["name"]} = {field["field_number"]};\n'

                    code += "    }\n"

            code += "}"

        elif proto["type"] == "enum":
            code += f"enum {name} {{\n"
            for value in proto["values"]:
                code += f'    {value["name"]} = {value["value"]};\n'
            code += "}"

        with open(os.path.join(sys.argv[2], f"{name}.proto"), "w") as f:
            f.write(code)