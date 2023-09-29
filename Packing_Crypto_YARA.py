import yara
import os

Path = os.path.dirname(__file__)



YARA_rules_path = Path+'/Yara_Rules/'

peid_rules = yara.compile(YARA_rules_path + 'peid.yar')
packer_rules = yara.compile(YARA_rules_path + 'packer.yar')
crypto_rules = yara.compile(YARA_rules_path + 'crypto.yar')

packers = [
    'AHTeam', 'Armadillo', 'Stelth', 'yodas', 'ASProtect', 'ACProtect', 'PEnguinCrypt', 
    'UPX', 'Safeguard', 'VMProtect', 'Vprotect', 'WinLicense', 'Themida', 'WinZip', 'WWPACK',
    'Y0da', 'Pepack', 'Upack', 'TSULoader'
    'SVKP', 'Simple', 'StarForce', 'SeauSFX', 'RPCrypt', 'Ramnit', 
    'RLPack', 'ProCrypt', 'Petite', 'PEShield', 'Perplex',
    'PELock', 'PECompact', 'PEBundle', 'RLPack', 'NsPack', 'Neolite', 
    'Mpress', 'MEW', 'MaskPE', 'ImpRec', 'kkrunchy', 'Gentee', 'FSG', 'Epack', 
    'DAStub', 'Crunch', 'CCG', 'Boomerang', 'ASPAck', 'Obsidium','Ciphator',
    'Phoenix', 'Thoreador', 'QinYingShieldLicense', 'Stones', 'CrypKey', 'VPacker',
    'Turbo', 'codeCrypter', 'Trap', 'beria', 'YZPack', 'crypt', 'crypt', 'pack',
    'protect', 'tect'
    ]

def Packing_Crypto_Detection(file_path, Directory_path):

    output_file = open(Directory_path+'/Packer_Cryptos.txt', "w")
    try:
        matches = crypto_rules.match(file_path)
        if matches:
            output_file.write("crypto detected..\n")
            output_file.write(str(matches))
            output_file.write('\n\n')
    except:
        output_file.write("Crypto Exception \n\n")

    try:
        matches = packer_rules.match(file_path)
        if matches:
            output_file.write('packers detected \n')
            output_file.write(matches+ ' \n\n')
    except:
        print('packer exception, you must read yara docs \n')
    

        
    try:
        matches = peid_rules.match(file_path)
        if matches:
            for match in matches:
                for packer in packers:
#in original code, the code will always go to except so, we need to access 'rule' field inside match(debug it to see what I mean)
                    if packer.lower() in match.rule.lower():   
                        output_file.write('packer detected \n')
                        output_file.write(packer+' \n')
            output_file.write('\n')
    except:
        print('Im here')
