import time
import logging
import networkx as nx
import networkx.drawing.nx_pydot as pdot
import matplotlib.pyplot as plt

from networkx.algorithms import dag
from networkx.algorithms import shortest_paths
from networkx.algorithms import tournament

# script input: call graph and icfg in dot format exported from the SVF engine
callgraph_path = "transfer/LMS-cg.dot" # call graph of the whole program
icfg_path = "transfer/LMS-icfg.dot"  # inter-procedure control flow graph of the whole program

ming48 = "transfer/swftophp048_icfg.dot"
libming = "transfer/swftophp-3071_icfg.dot"
cxxfilt = "transfer/cxxfilt-icfg.dot"
jasper = "transfer/jasper-2015-5221.dot"
lrzip = "transfer/lrzip2017-icfg.dot"
lrzip8 = "transfer/lrzip2018.dot"
objdump = "transfer/objdump-2017-icfg.dot"
readelf = "transfer/readelf-2017-icfg.dot"
objcopy = "transfer/objcopy-2017-icfg.dot"
listswf = "transfer/listswf-2016-icfg.dot"
xmllint = "transfer/xml-icfg.dot"
cjepg205 = "transfer/cjpeg205.dot"
cjepg205 = "transfer/cjpeg20_icfg.dot"
pngimage = "transfer/pngimage_icfg.dot"
pdfimages = "transfer/pdfimages_icfg.dot"
pdftoppm = "transfer/pdftoppm_icfg.dot"
pdftops = "transfer/pdftops_icfg.dot"
pdfdetach = "transfer/pdfdetach_icfg.dot"

test_cg = "test-cg.dot"
test_icfg = "test.dot"

# target_pos = "2016-4492"
# target_pos = "lrzip2018"
# target_pos = "CVE-2017-9049"
# target_pos = "CVE-2017-14940"
# target_pos = "CVE-2017-16828"
# target_pos = "CVE-2018-17360"
# target_pos = "CVE-2019-10871"
# target_pos = "CVE-2018-13785"
# target_pos = "CVE-2018-19060"
# target_pos = "CVE-2018-19059"
# target_pos = "CVE-2018-19058"
target_pos = "CVE-2020-13790"
target_info = {"libming3071": "parser.c:3071",
               "CVE-2016-9831":  "parser.c:64",
               "2016-4492": "cp-demangle.c:3729",
               "jasper2015": "jas_tvp.c:111",
               "lrzip2018": "stream.c:1756",
               "lrzip2017": "stream.c:1748",
               "CVE-2016-9827": "outputtxt.c:144",
               "CVE-2016-9829": "parser.c:1656",
               "CVE-2017-5969": "valid.c:1175",
               "CVE-2017-9047": "valid.c:1279",
               "CVE-2017-9049": "dict.c:448",
               "CVE-2017-9050": "dict.c:285",
               "CVE-2017-9988": "parser.c:2992",
               "CVE-2017-11728": "decompile.c:1508",
               "CVE-2017-11729": "decompile.c:868",
               "CVE-2017-11733": "util/decompile.c:1344",
               "CVE-2018-11095": "decompile.c:1932",
               "CVE-2018-8807": "decompile.c:868",
               "CVE-2018-8962": "decompile.c:398",
               "CVE-2018-11225": "decompile.c:2369",
               "CVE-2018-11226": "decompile.c:105",
               "CVE-2018-7868": "decompile.c:377",
               "CVE-2020-6628": "decompile.c:2015",
               "CVE-2018-20427": "decompile.c:425",
               "CVE-2019-9114": "decompile.c:258",
               "CVE-2019-12982": "decompile.c:3120",
               "CVE-2016-4487": "cplus-dem.c:4319",
               "CVE-2016-4489": "cplus-dem.c:4858",
               "CVE-2016-4490": "cp-demangle.c:1555",
               "CVE-2016-4491": "cp-demangle.c:4332",
               "CVE-2016-4492": "cp-demangle.c:3781",
               "CVE-2016-6131": "cplus-dem.c:2541",
               "CVE-2017-8392": "dwarf2.c:4212",
               "CVE-2017-8393": "elf.c:3568",
               "CVE-2017-8394": "objcopy.c:1553",
               "CVE-2017-8395": "cache.c:337",
               "CVE-2017-8396": "libbfd.c:615",
               "CVE-2017-8397": "reloc.c:885",
               "CVE-2017-8398": "dwarf.c:483",
               "CVE-2017-9038": "elfcomm.c:210",
               "CVE-2017-9039": "xmalloc.c:148",
               "CVE-2017-14940": "dwarf2.c:2907",
               "CVE-2017-16828": "dwarf.c:7535",
               "CVE-2017-7303": "elf.c:1257",
               "CVE-2018-17360": "libbfd.c:548",
               "CVE-2020-13790": "rdppm.c:434",
               "CVE-2018-13785": "pngrutil.c:3172",
               "CVE-2019-9200":  "Stream.cc:499",
               "CVE-2019-14494": "SplashOutputDev.cc:4622",
               "CVE-2019-10873": "SplashClip.cc:382",
               "CVE-2019-10872": "Splash.cc:5872",
               "CVE-2019-10871": "PSOutputDev.cc:3468",
               "CVE-2018-19060": "GooString.h:134",
               "CVE-2018-19059": "Object.h:397",
               "CVE-2018-19058": "Object.h:403",
               }

logging.basicConfig(filename="log-reachability/log-" + target_pos, level=logging.DEBUG)

# g = pdot.read_dot(test_icfg)

# g = pdot.read_dot(cxxfilt)
# g = pdot.read_dot(libming)
# g = pdot.read_dot(listswf)
# g = pdot.read_dot(ming48)
# g = pdot.read_dot(objdump)
# g = pdot.read_dot(readelf)
# g = pdot.read_dot(objcopy)
g = pdot.read_dot(cjepg205)
# g = pdot.read_dot(pngimage)
# g = pdot.read_dot(pdfimages)
# g = pdot.read_dot(pdftops)
# g = pdot.read_dot(pdftoppm)
# g = pdot.read_dot(pdfdetach)

print("read graph")
# g = pdot.read_dot(xmllint)

# print(tournament.is_tournament(g))


def find_node(G, name):
    ln = name.split(":")[1]
    file = name.split(":")[0]
    res = []
    for n, d in G.nodes(data=True):
        info = d.get('label', '')
        if len(info) > 1:
            if "ln: " + ln in info and file in info:
                print(d)
                res.insert(0, n)

    return res
    # return [n for n, d in G.nodes(data=True) if name in d.get('label', '') and "Entry" in d.get('label', '') ]


# def reachable_node_fast(G, node):
#     f_trace = []
#     b_trace = []
#
#     unsolve = node.copy()
#     init_func = ""
#
#     while len(unsolve) > 0:
#         cur = unsolve.pop(0)
#
#         current = G.nodes[cur]
#         # print(current)
#         current['visited'] = 'visited'
#
#         neighbors = list(G.predecessors(cur))
#         # print(neighbors)
#         for neighbor in neighbors:
#             if len(G.nodes[neighbor].get('visited', "")) == 0:
#                 unsolve.append(neighbor)
#
#         ir = current.get('label', '')
#         if len(ir) > 1:
#             # Function-level reachability analysis
#             # print("ir: ")
#             # print(ir)
#             pos = ir.find("Fun[")
#             if pos != -1:
#                 # print("find!")
#                 end = ir.find("]", pos)
#                 fname = ir[pos + 4:end]
#                 if len(init_func) == 0:
#                     init_func = fname
#                 if fname not in f_trace:
#                     f_trace.append(fname)
#             else:
#                 pos = ir.find("@_")
#                 if pos != -1:
#                     end = ir.find(",", pos)
#                     fname = ir[pos + 1:end]
#                     if fname not in f_trace:
#                         f_trace.append(fname)
#
#             # Block-level reachability analysis
#             debug_info = ir.split("\\n")[1]
#             # print("debug")
#             # print(debug_info)
#             pos = debug_info.find("ln: ")
#             if pos != -1:
#                 position = debug_info[pos:].split(" ")
#                 loc = position[1]
#                 file = position[3].split("/")[-1]
#                 bname = file + ":" + loc
#                 if bname not in b_trace:
#                     b_trace.append(bname)
#             else:
#                 pos = debug_info.find("line: ")
#                 if pos != -1:
#                     position = debug_info[pos:].split(" ")
#                     loc = position[1]
#                     file = position[3].split("/")[-1]
#                     bname = file + ":" + loc
#                     if bname not in b_trace:
#                         b_trace.append(bname)
#
#     unsolve = [node.copy().pop(0)]
#
#     # while len(unsolve) > 0:
#     #     cur = unsolve.pop(0)
#     #
#     #     current = G.nodes[cur]
#     #     # print(current)
#     #     current['visited'] = 'visited'
#     #
#     #     ir = current.get('label', '')
#     #     if len(ir) > 1:
#     #         # Function-level reachability analysis
#     #         # print("ir: ")
#     #         # print(ir)
#     #         pos = ir.find("Fun[")
#     #         if pos != -1 and "Exit()":
#     #             # print("find!")
#     #             continue
#     #         else:
#     #             pos = ir.find("@_")
#     #             if pos != -1:
#     #                 end = ir.find(",", pos)
#     #                 fname = ir[pos + 1:end]
#     #                 if fname not in f_trace:
#     #                     f_trace.append(fname)
#     #
#     #         # Block-level reachability analysis
#     #         debug_info = ir.split("\\n")[1]
#     #         # print("debug")
#     #         # print(debug_info)
#     #         pos = debug_info.find("ln: ")
#     #         if pos != -1:
#     #             position = debug_info[pos:].split(" ")
#     #             loc = position[1]
#     #             file = position[3].split("/")[-1]
#     #             bname = file + ":" + loc
#     #             if bname not in b_trace:
#     #                 b_trace.append(bname)
#     #         else:
#     #             pos = debug_info.find("line: ")
#     #             if pos != -1:
#     #                 position = debug_info[pos:].split(" ")
#     #                 loc = position[1]
#     #                 file = position[3].split("/")[-1]
#     #                 bname = file + ":" + loc
#     #                 if bname not in b_trace:
#     #                     b_trace.append(bname)
#     #
#     #     neighbors = list(G.successors(cur))
#     #     for neighbor in neighbors:
#     #         if len(G.nodes[neighbor].get('visited', "")) == 0:
#     #             unsolve.append(neighbor)
#
#     return f_trace, b_trace


def reachable_node_fast_new(G, node):
    f_trace = []
    b_trace = []

    unsolve = node.copy()
    init_func = ""

    while len(unsolve) > 0:
        cur = unsolve.pop(0)

        current = G.nodes[cur]
        # print(current)
        current['visited'] = 'visited'

        neighbors = list(G.predecessors(cur))
        # print(neighbors)
        for neighbor in neighbors:
            if len(G.nodes[neighbor].get('visited', "")) == 0:
                unsolve.append(neighbor)

        ir = current.get('label', '')
        if len(ir) > 1:
            # Function-level reachability analysis
            # print("ir: ")
            # print(ir)
            pos = ir.find("Fun[")
            if pos != -1:
                # print("find!")
                end = ir.find("]", pos)
                fname = ir[pos + 4:end]
                if len(init_func) == 0:
                    init_func = fname
                if fname not in f_trace:
                    f_trace.append(fname)
            else:
                pos = ir.find("@_")
                if pos != -1:
                    end = ir.find(",", pos)
                    fname = ir[pos + 1:end]
                    if fname not in f_trace:
                        f_trace.append(fname)

            # Block-level reachability analysis
            debug_info = ir.split("\\n")[1]
            # print("debug")
            # print(debug_info)
            pos = debug_info.find("ln: ")
            if pos != -1:
                position = debug_info[pos:].split(" ")
                loc = position[1]
                file_pos = debug_info.find("fl: ")
                file = debug_info[file_pos:].split(" ")[1]
                pure_file = file.split("/")[-1]
                bname = pure_file + ":" + loc
                if bname not in b_trace:
                    b_trace.append(bname)
            else:
                pos = debug_info.find("line: ")
                if pos != -1:
                    position = debug_info[pos:].split(" ")
                    loc = position[1]
                    file = position[3].split("/")[-1]
                    bname = file + ":" + loc
                    if bname not in b_trace:
                        b_trace.append(bname)

    unsolve = [node.copy().pop(0)]

    # while len(unsolve) > 0:
    #     cur = unsolve.pop(0)
    #
    #     current = G.nodes[cur]
    #     # print(current)
    #     current['visited'] = 'visited'
    #
    #     ir = current.get('label', '')
    #     if len(ir) > 1:
    #         # Function-level reachability analysis
    #         # print("ir: ")
    #         # print(ir)
    #         pos = ir.find("Fun[")
    #         if pos != -1 and "Exit()":
    #             # print("find!")
    #             continue
    #         else:
    #             pos = ir.find("@_")
    #             if pos != -1:
    #                 end = ir.find(",", pos)
    #                 fname = ir[pos + 1:end]
    #                 if fname not in f_trace:
    #                     f_trace.append(fname)
    #
    #         # Block-level reachability analysis
    #         debug_info = ir.split("\\n")[1]
    #         # print("debug")
    #         # print(debug_info)
    #         pos = debug_info.find("ln: ")
    #         if pos != -1:
    #             position = debug_info[pos:].split(" ")
    #             loc = position[1]
    #             file = position[3].split("/")[-1]
    #             bname = file + ":" + loc
    #             if bname not in b_trace:
    #                 b_trace.append(bname)
    #         else:
    #             pos = debug_info.find("line: ")
    #             if pos != -1:
    #                 position = debug_info[pos:].split(" ")
    #                 loc = position[1]
    #                 file = position[3].split("/")[-1]
    #                 bname = file + ":" + loc
    #                 if bname not in b_trace:
    #                     b_trace.append(bname)
    #
    #     neighbors = list(G.successors(cur))
    #     for neighbor in neighbors:
    #         if len(G.nodes[neighbor].get('visited', "")) == 0:
    #             unsolve.append(neighbor)

    return f_trace, b_trace

# def reachable_node(G, node):
#     f_trace = []
#     b_trace = []
#     for n, d in G.nodes(data=True):
#         # print(n)
#         # res = dag.ancestors(G, node)
#         # print(res)
#         if shortest_paths.has_path(G, n, node):
#             # print(n, " ", d)
#
#             ir = d.get('label', '')
#             if len(ir) > 1:
#                 # Function-level reachability analysis
#                 # print("ir: ")
#                 # print(ir)
#                 pos = ir.find("Fun[")
#                 if pos != -1:
#                     # print("find!")
#                     end = ir.find("]", pos)
#                     fname = ir[pos+4:end]
#                     if fname not in f_trace:
#                         f_trace.append(fname)
#
#                 # Block-level reachability analysis
#
#                 debug_info = ir.split("\\n")[1]
#                 # print("debug")
#                 # print(debug_info)
#                 pos = debug_info.find("ln: ")
#                 if pos != -1:
#                     position = debug_info[pos:].split(" ")
#                     loc = position[1]
#                     file = position[3].split("/")[-1]
#                     b_trace.append(file + ":" + loc)
#
#     return f_trace, b_trace


def pre_processing(g):
    aux_edges = {}
    # add edges for context sensitivity
    for node in g.nodes():
        # node = node.split(":")[0]
        # print(node)
        tmp = node.split(":")
        if len(tmp) > 1:
            values = aux_edges.get(tmp[0], [])
            values.append(node)
            aux_edges[tmp[0]] = values
            # print(tmp[0])
            # print(aux_edges.keys())
            # if str(tmp[0]) in aux_edges.keys():
            #     aux_edges[str(tmp[0])] = [node]
            # else:
            #     aux_edges[str(tmp[0])].append(node)

    for key, values in aux_edges.items():
        for context in values:
            g.add_edge(key, context)
            g.add_edge(context, key)

    return g

print("======================preprpcessing=======================")
start = time.time()
g1 = pre_processing(g)
processing = time.time()
print("======================split=======================")
logging.info("processing time: " + str(processing - start))
# for edge in g.edges(data=True):
#     print(edge)
# print(g.edges())

target = find_node(g, target_info[target_pos])
print(target)
logging.info(target)

locating = time.time()
print("==================split-reachable=================")
logging.info("location time: " + str(locating - processing))

f_trace, b_trace = reachable_node_fast_new(g, target)

reachability = time.time()
print("====================split-ftrace==================")
logging.info("reachability time: " + str(reachability - locating))

f_trace = sorted(set(f_trace))
print("num of fuc: " + str(len(f_trace)))

print("======split-btrace=======")
b_trace = sorted(set(b_trace))
print("num of ins: " + str(len(b_trace)))

print("======split-output=======")
with open("ftrace-" + target_pos + ".txt", "w") as f:
    for item in f_trace:
        f.write(item + "\n")

    f.close()

with open("bbreaches-" + target_pos + ".txt", "w") as f:
    for item in b_trace:
        if item == target_info[target_pos]:
            f.write(item + ";TARGET\n")
        else:
            f.write(item + "\n")

    f.close()

end = time.time()
print("reachability time: " + str(reachability - locating))
logging.info("overall timing: " + str(end - start))

# for node in g.nodes(data=True):
#     print(node)
#     # print(node[1])
#     if "label" in node[1].keys():
#         print(node[1]["label"])

# print("===================================edge======================================")
# for edge in g.edges(data = True):
#     print(edge)

# nx.draw(g1, with_labels=True)
# plt.show()
# plt.savefig("tex")
