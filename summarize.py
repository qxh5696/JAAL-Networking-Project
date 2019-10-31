"""

    Module containing the implmentation to the summarization module.

    @authors Qadir Haqq, Theodora Bendlin

"""
import numpy as np
import pandas as pd
from sklearn.cluster import k_means

'''
    Main summarization function for a batch of packets. Performs the following steps:

    (1) Filtering and normalization
    (2) Dimensionality reduction (fields and packets modes)
    (3) Final representation construction

    @parameter df (Dataframe) packet dataframe containing a batch of size "n"
'''
def summarize_packet_data(df):

    # Normalization step to bound values between 0 and 1
    normalized_df = normalize_packet_dataframe(df)

    perform_svd_decomp(normalized_df, 5)
    

    # # apply reduction
    # reduced_df = np.linalg.svd(normalized_df.values)
    # # kmeans
    # clusters = k_means(reduced_df, NUM_CLUSTERS)
    # return clusters

'''

    Normalizes the packet header values for a n x p matrix
    X. 

    @parameter df (DataFrame) the original dataframe of integer values
    @returns normalized_df (Dataframe) normalized dataframe
'''
def normalize_packet_dataframe(df):
    
    # Create copy to retain integrity of original values
    normalized_df = df.copy()

    for c in normalized_df.columns:
        normalized_df[c].apply(lambda x: x/normalized_df[c].max() if normalized_df[c].max() != 0 else 0)

    return normalized_df

def perform_svd_decomp(df, r):
    df = df.dropna(axis=0)

    np_array = df.to_numpy(dtype='float32', copy=True)
    u, sig, vt = np.linalg.svd(np_array)

    # Rank can be further reduced by setting r largest values to themselves,
    # and the rest to zero
    sig_r = sig
    largest_indexes = np.argpartition(sig_r, -r)[-r:]
    for idx in range(0, len(sig_r)):
        if idx not in largest_indexes:
            sig_r[idx] = 0
    
    # Since we are only keeping the top r values, we can throw away
    # unimportant columns as well
    u_r = u
    vt_r = vt
    for col in range(len(np_array[0])):
        if col not in largest_indexes:
            u_r = np.delete(u_r, col, axis=1)
            vt_r = np.delete(vt_r, col, axis=1)
    
    print("Shape u: ", u_r.shape)
    print("Shape s: ", sig_r.shape)
    print("Shape v: ", vt_r.shape)

    # You were working on correctly deleting the rows from the other two matricies to finish up SVD
    
    #prod = np.dot(u, sig_r)
    #return np.dot(prod, vt_r)

