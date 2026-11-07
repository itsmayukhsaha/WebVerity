import sys, os
sys.path.insert(0, "..")
import backend.app.intelligence.indicator_matcher as m
print(m.__file__)
print(m.normalize_indicator("HTTPS://Example.COM:443/path/?token=secret"))
