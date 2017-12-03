#!/usr/bin/python
from ConfigUtils import getBaseConfig
from LogUtils import getModuleLogger


import Levenshtein
import numpy as np
import os
import re
import sklearn.cluster


cDir = os.path.dirname(os.path.realpath(__file__))
rootDir = os.path.abspath(os.path.join(cDir, os.pardir))
baseConfig = getBaseConfig(rootDir)
logging = getModuleLogger(__name__)


def tokeniseUrl(in_url):
    no_prefix = in_url.split('://')[1] # no prefix.
    no_suffix = no_prefix.split('?')[0] # remove query strings.
    no_symbol = re.sub('[^a-zA-Z0-9 \n\.]', ' ', no_suffix) # remove symbols.
    clean_url = re.sub(' +',' ', no_symbol) # remove multiple spaces.
    return clean_url


def getSignificantItems(item_list):
    tokenised_list = []

    logging.info('Tokenising input data.')
    for item in item_list:
        tokenised_list.append(tokeniseUrl(item))

    items = np.asarray(item_list)
    tokenised_items = np.asarray(tokenised_list)
    logging.info('Calculating Levenshtein distances between items.')
    lev_similarity = -1*np.array([[Levenshtein.distance(i1,i2) for i1 in tokenised_items] for i2 in tokenised_items])

    logging.info('Applying affinity propagation to data.')
    aff_prop = sklearn.cluster.AffinityPropagation(affinity='precomputed', damping=0.7)
    aff_prop.fit(lev_similarity)

    logging.info('Completed! Assembling list.')
    output_list = []

    for cluster_id in np.unique(aff_prop.labels_):
        exemplar = items[aff_prop.cluster_centers_indices_[cluster_id]]
        output_list.append(exemplar)
    
    return output_list
