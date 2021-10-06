#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    Script permettant de recuperer les flux rss des nvd et cert et de les analyser avant de faire un dashboard sur un site flask
"""

#Importation des modules necessaire
import os
import feedparser
import re
import requests
from bs4 import BeautifulSoup
import sqlite3
from flask import Flask 
import logging

if os.path.isfile('log.txt'):
    os.remove('log.txt')
lg.basicConfig(filename='log.txt', filemode='a', format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',datefmt='%H:%M:%S',level=lg.INFO)


def create_DB(cur, con):
    """
        Fonction pour creer une base de donne
    """
    lg.info("create_DB - Creation des tables")
    #Creation de la table
    req = '''CREATE TABLE Vuln_NVD (ID text, Link_NVD text, Description text, Link_CVE text, NIST text, BaseScore text, NVD_Published_Date text, NVD_Last_Modified text, Vector text)'''
    cur.execute(req)
    lg.info("create_DB - Execution : " + req)
    req = '''CREATE TABLE Vuln_CERT (ID text, Link_CERT text, Ref text, Date text, Tags text, Name text, Size text, Type text, MD5 text, SHA1 text, SHA256 text, SHA512 text, ssdeep text, Entropy text, Antivirus text, YARA_Rules text, ssdeep_Matches text, Description text, Reco text)'''
    cur.execute(req)
    lg.info("create_DB - Execution : " + req)
    # Save (commit) the changes
    con.commit()

def getFlux(url, filename, con, cur, tableName):
    """
        Fonction pour recuperer les infos du flux RSS et les ecrire dans un fichier de sortie
    """
    lg.info("getFlux - Recuperation flux au format xml : " + url)

    #Recuperation du fichier xml
    response = requests.get(url)
    with open(filename, 'wb') as file:
        file.write(response.content)

    
    # Création d'une instance
    news_feed = feedparser.parse(filename)

    for entry in news_feed.entries:
        title =  re.sub('<[^<]+?>', '', entry.title)
        # Insert a row of data
        if tableName == 'Vuln_NVD':
            req = "INSERT INTO " + tableName + " SELECT '" + \
            title.replace("'", "") +"','"+entry['link'].replace("'", "")+"', '"+entry['summary'].replace("'", "")+"','','','','','',''" + \
            "WHERE NOT EXISTS(SELECT 1 FROM " + tableName + " WHERE ID = '" + title.replace("'", "") + "')")
            cur.execute(req)
            
            lg.info("getFlux - Ececution : " + req)
        else:
            req = "INSERT INTO " + tableName + " SELECT '" + \
            title.replace("'", "") +"','"+entry['link'].replace("'", "")+"', '"+entry['summary'].replace("'", "")+"','','','','','', '', '', '', '', '', '', '', '', '', '', ''" + \
            "WHERE NOT EXISTS(SELECT 1 FROM " + tableName + " WHERE ID = '" + title.replace("'", "") + "')"
            cur.execute(req)
            
            lg.info("getFlux - Ececution : " + req)
        else:
        # Save (commit) the changes
        con.commit()


def getInfoNvd(filename, con, cur, tableName):
    """
        Fonction pour recuperer information sur chaque ndv
    """

    lg.info("getInfoNvd - Recuperation information vuln NVD")

    #Tableau avec les requete
    req = []

    if tableName == 'Vuln_NVD':
        #Lecture du fichier resultat
        for row in cur.execute("SELECT * FROM " + tableName):
            if row[3] == '':
                #Recuperation url de la nvd
                url = row[1]
                rep = requests.get(url)
                
                lg.info("getInfoNvd - Navigation sur " + url + " pour recherche infos")

                #On recupere les infos sur l'url
                dicoInfo = {}
                dicoInfo['CVE_Link'] = findHtmlTextNVD(rep, 'vuln-cve-dictionary-entry', 'a', False, 'href')
                dicoInfo['NIST'] = findHtmlTextNVD(rep, 'vuln-cvss3-panel-source', 'span')
                dicoInfo['BaseScore'] = findHtmlTextNVD(rep, 'vuln-cvss3-panel-score', 'a')
                dicoInfo['NVD_Published_Date'] = findHtmlTextNVD(rep, 'vuln-published-on', 'span')
                dicoInfo['NVD_Last_Modified'] = findHtmlTextNVD(rep, 'vuln-last-modified-on', 'span')
                dicoInfo['Vector'] = findHtmlTextNVD(rep, 'vuln-cvss3-nist-vector', 'span')
                
                #On ajoute dans le dico de requete
                requete = "UPDATE " + tableName + " SET LINK_CVE = '" + str(dicoInfo['CVE_Link']) +"', \
                    NIST = '" + str(dicoInfo['NIST']) +"', \
                    BaseScore = '" + str(dicoInfo['BaseScore']) +"', \
                    NVD_Published_Date = '" + str(dicoInfo['NVD_Published_Date']) +"', \
                    NVD_Last_Modified = '" + str(dicoInfo['NVD_Last_Modified']) +"', \
                    Vector = '" + str(dicoInfo['Vector']) +"' \
                    WHERE ID = '" + row[0] + "'"
                req.append(requete)
                
                lg.info("getInfoNvd - AJout requete : " + requete)
    else:
        #Lecture du fichier resultat
        for row in cur.execute("SELECT * FROM " + tableName):
            if row[3] == '':
                #Recuperation url de la nvd
                url = row[1]
                rep = requests.get(url)
                
                lg.info("getInfoNvd - Navigation sur " + url + " pour recherche infos")

                #On recupere les infos sur l'url
                dicoInfo = {}
                dicoInfo['tag'] = findHtmlTextCERT(rep, 'cma-tag cma-tag-warning', 'span')
                dicoInfo['Name'] = findHTMLTextInTabCert(rep, 'cma-content cma-left cma-hashes', 'Name')
                dicoInfo['Size'] = findHTMLTextInTabCert(rep, 'cma-content cma-left cma-hashes', 'Size')
                dicoInfo['Type'] = findHTMLTextInTabCert(rep, 'cma-content cma-left cma-hashes', 'Type')
                dicoInfo['MD5'] = findHTMLTextInTabCert(rep, 'cma-content cma-left cma-hashes', 'MD5')
                dicoInfo['SHA1'] = findHTMLTextInTabCert(rep, 'cma-content cma-left cma-hashes', 'SHA1')
                dicoInfo['SHA256'] = findHTMLTextInTabCert(rep, 'cma-content cma-left cma-hashes', 'SHA256')
                dicoInfo['SHA512'] = findHTMLTextInTabCert(rep, 'cma-content cma-left cma-hashes', 'SHA512')
                dicoInfo['ssdeep'] = findHTMLTextInTabCert(rep, 'cma-content cma-left cma-hashes', 'ssdeep')
                dicoInfo['Entropy'] = findHTMLTextInTabCert(rep, 'cma-content cma-left cma-hashes', 'Entropy')
                dicoInfo['Date'] = str(findHtmlTextCERT(rep, 'submitted meta-text', 'div')).split(":")[1].split("\n")[0].replace(" ", "")[:-3]
                dicoInfo['Antivirus'] = getNextHtmlElm(rep, 'cma-data-title', 'h5', 'Antivirus')
                dicoInfo['YARA_Rules'] = getNextHtmlElm(rep, 'cma-data-title', 'h5', 'YARA Rules')
                dicoInfo['ssdeep_Matches'] = getNextHtmlElm(rep, 'cma-data-title', 'h5', 'ssdeep Matches')
                dicoInfo['Description'] = getNextHtmlElm(rep, 'cma-data-title', 'h5', 'Description')
                dicoInfo['Reco'] = getNextHtmlElm(rep, 'cma-section-title', 'h3', 'Recommendations')
                
                #On ajoute dans le dico de requete
                requete = "UPDATE " + tableName + " SET Tags = '" + str(dicoInfo['tag']) +"', \
                    Name = '" + str(dicoInfo['Name']) +"', \
                    Date = '" + str(dicoInfo['Date']) +"', \
                    Size = '" + str(dicoInfo['Size']) +"', \
                    Type = '" + str(dicoInfo['Type']) +"', \
                    MD5 = '" + str(dicoInfo['MD5']) +"', \
                    SHA1 = '" + str(dicoInfo['SHA1']) +"', \
                    SHA256 = '" + str(dicoInfo['SHA256']) +"', \
                    SHA512 = '" + str(dicoInfo['SHA512']) +"', \
                    ssdeep = '" + str(dicoInfo['ssdeep']) +"', \
                    Entropy = '" + str(dicoInfo['Entropy']) +"', \
                    Antivirus = '" + str(dicoInfo['Antivirus']) +"', \
                    YARA_Rules = '" + str(dicoInfo['YARA_Rules']) +"', \
                    ssdeep_Matches = '" + str(dicoInfo['ssdeep_Matches']) +"', \
                    Description = '" + str(dicoInfo['Description']) +"', \
                    Reco = '" + str(dicoInfo['Reco']) +"' \
                    WHERE ID = '" + row[0] + "'"
                req.append(requete)
                
                lg.info("getInfoNvd - AJout requete : " + requete)

    #On applique les requete
    for elm in req:
        cur.execute(elm)
    # Save (commit) the changes
    con.commit()


def findHtmlTextNVD(rep, attribut, balise, text=True, attributToGet=None):
        """
            Methode pour retrouver du text en parsant du HTML
        """
        lg.info("findHtmlTextNVD - On parse le fichier HTML")
        soup = BeautifulSoup(rep.text, 'html.parser')

        for a in soup.find_all(balise):
            if attribut in a.attrs.values():
                if text == True:
                    return a.text
                else:
                    return a.attrs[attributToGet]


def findHtmlTextCERT(rep, attribut, balise):
        """
            Methode pour retrouver du text en parsant du HTML
        """
        lg.info("findHtmlTextCERT - On parse le fichier HTML")
        soup = BeautifulSoup(rep.text, 'html.parser')
        rep = []
        for a in soup.find_all(balise, {"class" : attribut}):
            rep.append(a.text.strip("'"))
        return str(list(set(rep))).replace("'", "")


def getNextHtmlElm(rep, attribut, balise, txt):
        """
            Methode pour retrouver du text en parsant du HTML
        """
        lg.info("getNextHtmlElm - On parse le fichier HTML")
        soup = BeautifulSoup(rep.text, 'html.parser')
        rep = []
        for a in soup.find_all(balise, {"class" : attribut}):
            if a.text == txt:
                rep = a.findNext('p')
                return rep.text.replace("'", "")


def findHTMLTextInTabCert(rep, classTable, col):
    """
        Fonctin pour retrouver une valeur dans un tableau en fonction de la colonne en entre
    """
    lg.info("findHTMLTextInTabCert - On parse le fichier HTML")
    soup = BeautifulSoup(rep.text, 'html.parser')
    rows = iter(soup.find('table', {"class" : classTable}).find_all('tr'))
    for row in rows:
        if col in str(row):
            rep = str(row)[str(row).find('<td>')+4:str(row).find('</td>')]
            return rep.replace("'", "")
        

def nettoyage(fichierToSuppr):
    """
        Fonction pour nettoyer les fichier temporaire
    """
    lg.info("nettoyage - On supprime les fichiers temporaire")
    for elm in fichierToSuppr:
        if os.path.isfile(elm):
            os.remove(elm)


if __name__ == "__main__":

    lg.info("main - Début du programme")

    #Creation de la database NVD si premiere fois:
    if not os.path.isfile('data.db'):
        #Connexon à la base de deoone
        con = sqlite3.connect('data.db')
        cur = con.cursor()
        #Cration Table
        create_DB(cur, con)
    else:
        #Connexon à la base de deoone
        con = sqlite3.connect('data.db')
        cur = con.cursor()

    #Recuperation rss cert et nvd
    url_cert = 'https://us-cert.cisa.gov/ncas/analysis-reports.xml'
    filename_cert = 'feed_cert.xml'
    url_nvd = 'https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml'
    filename_nvd = 'feed_nvd.xml'

    for elm in [[url_cert, filename_cert, 'Vuln_CERT'], [url_nvd, filename_nvd, 'Vuln_NVD']]:
        #recuperation du flux brut
        getFlux(elm[0], elm[1], con, cur, elm[2])

        #Recuperation information pour chaque ndv
        getInfoNvd(filename_nvd.replace("xml", "txt"), con, cur, elm[2])

    #Fermeture base de donnes
    con.close()

    #Nettoyage fichier temporaire
    nettoyage([filename_cert, filename_nvd]) 

    lg.info("main - Fin du programme")