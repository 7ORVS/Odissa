import r2pipe

Commands = {

    'it': "Hashes.txt",
    'i': "General Information.txt",
    'il': "DLLs.txt",
    'ii': "Imports.txt",
    'iE': "Exports.txt",
    'iS': "Sections.txt",
    'iR': "Resources.txt",
    'izz': "Strings.txt"
}



def StaticAnalysis (R2_Object, Directory_Path):

    for command in Commands:
        output_file = open(Directory_Path+'/'+Commands[command], "w") 
        content = R2_Object.cmd(command)
        output_file.write(content)
        


def GetStaticAnalysisInformation (Binary_Path,Directory_Path):
        r2 = r2pipe.open(Binary_Path)
        StaticAnalysis(r2,Directory_Path)

