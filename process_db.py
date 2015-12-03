#!python3
import argparse
import sqlite3
import os

def main():
    """ 1) Fill in all null values with 0s
        2) Normalize all data
        3) Any additional options
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--svm", action="store_true", help="output svm file?")
    args = parser.parse_args()
    
    if(not os.path.exists("samples.db")):
        print("Expected samples.db in path.  Use net_preprocess.py first.")
        exit(1)
        
    autofill_nulls("samples")
    normalize_data("samples")
    
    autofill_nulls("udp_samples")
    normalize_data("udp_samples")
    
    autofill_nulls("tcp_samples")
    normalize_data("tcp_samples")
    
    autofill_nulls("icmp_samples")
    normalize_data("icmp_samples")
    
def autofill_nulls(table):
    """
    """
    conn = sqlite3.connect("samples.db")
    c = conn.cursor()
    
    # Names of all column
    c.execute('''SELECT * FROM %s''' % (table))
    column_names = [description[0] for description in c.description]

    c.execute('''SELECT * FROM %s''' % (table))
    samples = c.fetchall()
    for sample in samples:
        for idx, column in enumerate(column_names):
            if(column != "uuid"):
                if(sample[idx] == None):
                    new_value = 0
                    # Update db with new value
                    c.execute('''UPDATE %s SET %s=%d WHERE uuid=%d''' % (table, column, new_value, sample[0]))
        conn.commit()
    conn.close()

def normalize_data(table):
    """
    """
    conn = sqlite3.connect("samples.db")
    c = conn.cursor()
    
    # Names of all column
    c.execute('''SELECT * FROM %s''' % (table))
    column_names = [description[0] for description in c.description]
    
    # Get min,max of all columns
    column_props = {}
    for column in column_names:
        if(column != "uuid"):
            c.execute('''SELECT MIN(%s), MAX(%s) FROM %s''' % (column, column, table))
            column_props[column] = c.fetchone()[:2]

    c.execute('''SELECT * FROM %s''' % (table))
    samples = c.fetchall()
    for sample in samples:
        new_values = []
        for idx, column in enumerate(column_names):
            if(column != "uuid" and column != "class"):
                # Avoid div by zero errros
                if(column_props[column][1] != 0):
                    # Update value to be (value - min)/(max - min)
                    new_value = ((sample[idx] - column_props[column][0])/(column_props[column][1] - column_props[column][0]))
                    # Update db with new value
                    c.execute('''UPDATE %s SET %s=%f WHERE uuid=%d''' % (table, column, new_value, sample[0]))
        conn.commit()
    conn.close()

def sql_2_libsvm():
    #Turn sql data into lib svm format
    #lib svm format: <label> <feature_idx>:<feature_value> <feature_idx>:<feature_value> ...
    #also scale any non-binary data from 0 to 1.
    return
    
if __name__ == "__main__": main()