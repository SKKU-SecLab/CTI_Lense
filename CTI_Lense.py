import os
from CTIAnalyzer import Volume, Diversity, Timeliness, Quality
from argparse import ArgumentParser

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-e", type=str, help="You can see individual results for one of volume, diversity, timeliness, and qaulity. Please, choose one of volume, diversity, timeliness, and qaulity. If you choose none, the code will shows all results", dest="etype")

    args = parser.parse_args()

    if args.etype:
        etype = args.etype

    
    if etype == "volume":
        print ("Volume")
        Volume.table1_volume_source()
        print ("")

    elif etype == "diversity":
        print ("Diversity")
        diversity = Diversity.Diversity()
        diversity.table3_ObjAttrCoverage()
        print ("")
        diversity.table6_IndicatorAttrCoverage()
        print ("")

    elif etype == "timeliness":
        print ("Timeliness")
        timeliness = Timeliness.Timeliness()
        timeliness.causality_test()
        print ("")

    elif etype == "quality":
        print ("Quality")
        quality = Quality.Quality()
        quality.fig4_correctness()
        print ("")
        quality.fig7_completeness()
        print ("")
        quality.table4_scanning_result()
        print ("")
        quality.table5_correctly_mapped()
        print ("")
        quality.fig5_accuracy_vtt()

    else:
        print ("Volume")
        Volume.table1_volume_source()

        print ("")
        
        print ("Diversity")
        diversity = Diversity.Diversity()
        diversity.table3_ObjAttrCoverage()
        print ("")
        diversity.table6_IndicatorAttrCoverage()

        print ("")

        print ("Timeliness")
        timeliness = Timeliness.Timeliness()
        timeliness.causality_test()
        print ("")

        print ("Quality")
        quality = Quality.Quality()
        quality.fig4_correctness()
        print ("")
        quality.fig7_completeness()
        print ("")
        quality.table4_scanning_result()
        print ("")
        quality.table5_correctly_mapped()
        print ("")
        quality.fig5_accuracy_vtt()
