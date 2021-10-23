#Crie um código em Python que receba o path de um executável via parâmetro, 
# parseie o arquivo executável para exibir todas as funções utilizadas. 
# Para fazer essa tarefa é necessário utilizar uma lib python de parseamento de arquivos PE.

from capstone import *
from capstone.x86 import *
import pefile
import pathlib as  pl

"""
Essa função pega inicialmente todo o código e data no PE Header do programa, as sections, contendo as informações e funções
usadas na execução do código/Parametro sections
O segundo parâmetro é o endereço na memória da primeira instrução desse bloco, essa separação é feita justamente para conseguir
o código principal e suas funções
"""
def get_main_code_section(sections, base_of_code):
    addresses = []
    #Loop para concatenar todos as seções do código em addresses
    #Uma versão para visualização dessa parte somente está em:
    #https://commie.io/#J9Mp0asm
    for section in sections: 
        addresses.append(section.VirtualAddress)

    #Verifica se o endereço realmente retorna a primeira instrução
    #Se sim, ela retorna a mesma, se não, ele faz um ordenamento 
    #e retorna partição de memória que o código pertence
    if base_of_code in addresses:    
        return sections[addresses.index(base_of_code)]
    else:
        addresses.append(base_of_code)
        addresses.sort()
        if addresses.index(base_of_code)!= 0:
            return sections[addresses.index(base_of_code)-1]
        else:
            #Não foi possível localizar nada
            return None

def fine_disassemble(exe):
    #Usa o método para adquirir a base do código
    main_code = get_main_code_section(exe.sections, exe.OPTIONAL_HEADER.BaseOfCode)

    #Define a arquitertura da máquina
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    last_address = 0
    last_size = 0

    #Separa o intervalo no qual foi posto o bloco de código
    begin = main_code.PointerToRawData
    #Fim de primeira partição da memória alocada para o código
    end = begin+main_code.SizeOfRawData

    while True:
        #Parseamento e desconstrução do código e suas funções lógico-aritméticas
        data = exe.get_memory_mapped_image()[begin:end]
        for i in md.disasm(data, begin):
            print(i)
            last_address = int(i.address)
            last_size = i.size
        #Pulam-se alguns bytes de memória à partir do endereçamento da mesma
        begin = max(int(last_address),begin)+last_size+1
        if begin >= end:
            print("out")
            break


inputfp = str(input("Insira o nome do executável:\n"))
executable = inputfp+".exe"
exe_file_path = pl.Path(__file__).parent.absolute().joinpath(executable)


try:
  exe = pefile.PE(exe_file_path)
  try:
    fine_disassemble(exe)
  except:
    print("Este arquivo possui alguma falha em sua construção ou está corrompido")
except:
  print("Arquivo não encontrado ou não compatível")


"""
Os PEs utilizados para testar esse programa foram:
putty.exe
Encontrado em:https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html
autoclicker.exe
Encontrado em:https://sourceforge.net/projects/orphamielautoclicker/

Para aprofundamento teórico desse programa,  pode-se utilizar as seguintes referências:
https://www.youtube.com/watch?v=vQPz3QFDR3c
https://github.com/erocarrera/pefile
https://www.capstone-engine.org/lang_python.html
"""