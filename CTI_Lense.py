import os
from CTIAnalyzer import Volume, Diversity, Timeliness, Quality
from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument("-e", type=str, help="You can see individual results for one of volume, diversity, timeliness, and quality. Please choose one of volume, diversity, timeliness, and quality. If you choose none, the code will show all results", dest="etype")

args = parser.parse_args()

# Check if the analysis type is specified
if args.etype:
    etype = args.etype

# Perform analysis based on the specified type or show all results
if etype == "volume":
    # If the type is volume, print the analysis type, perform volume analysis, and print a blank line
    print("Volume")
    Volume.table1_volume_source()
    print("")

elif etype == "diversity":
    # If the type is diversity, print the analysis type, create a Diversity object, and perform diversity analyses
    print("Diversity")
    diversity = Diversity.Diversity()
    diversity.table3_ObjAttrCoverage()
    print("")
    diversity.table6_IndicatorAttrCoverage()
    print("")

elif etype == "timeliness":
    # If the type is timeliness, print the analysis type, create a Timeliness object, and perform timeliness analyses
    print("Timeliness")
    timeliness = Timeliness.Timeliness()
    timeliness.causality_test()
    print("")

elif etype == "quality":
    # If the type is quality, print the analysis type, create a Quality object, and perform quality analyses
    print("Quality")
    quality = Quality.Quality()
    quality.fig4_correctness()
    print("")
    quality.fig7_completeness()
    print("")
    quality.table4_scanning_result()
    print("")
    quality.table5_correctly_mapped()
    print("")
    quality.fig5_accuracy_vtt()

else:
    # If no specific type is specified, show results for all analysis types
    print("Volume")
    Volume.table1_volume_source()
    print("")

    print("Diversity")
    diversity = Diversity.Diversity()
    diversity.table3_ObjAttrCoverage()
    print("")
    diversity.table6_IndicatorAttrCoverage()
    print("")

    print("Timeliness")
    timeliness = Timeliness.Timeliness()
    timeliness.causality_test()
    print("")

    print("Quality")
    quality = Quality.Quality()
    quality.fig5_correctness()
    print("")
    quality.fig8_completeness()
    print("")
    quality.table7_scanning_result()
    print("")
    quality.table4_correctly_mapped()
    print("")
    quality.fig6_accuracy_vtt()
