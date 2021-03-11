import collections
from datetime import datetime

import neo4j
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render, redirect
from neo4j import GraphDatabase
import neo4jupyter

neo4jUsername = "neo4j"
neo4jPassword = "max"

# from libcypher_parser import parse_statement
from SlaGenerator.forms import MACMForm
from SlaGenerator.models import MACM, Asset, Asset_type, Relation, Protocol


def apps_management(request):
    ordered_apps = []
    context = {}
    try:
        graphDriver = GraphDatabase.driver(uri="bolt://localhost:7687", auth=(neo4jUsername, neo4jPassword))
        session = graphDriver.session()
        nodes_string = session.run("match (node) return node")
        nodes = [record for record in nodes_string.data()]
        apps = {}
        for node in nodes:
            try:
                apps[node['node']['app_id']] = node['node']['application']
            except:
                print("Cannot parse graph with node " + str(node['node']))
                break
        ordered_apps = collections.OrderedDict(sorted(apps.items()))
        # print(ordered_apps)
        for appId, application in ordered_apps.items():
            # print(appId + " " + application)
            MACM_instance = MACM(appId=appId, application=application)
            if not MACM_instance:
                MACM_instance.save()
            graphDriver.close()
        context = {
            'apps': ordered_apps
        }
    except neo4j.exceptions.ServiceUnavailable as error:
        print(error)
        context = {
            'error': error
        }

    return render(request, 'apps_management.html', context)


def get_graphNodesbyAppId(appId):
    graph = GraphDatabase.driver(uri="bolt://localhost:7687", auth=(neo4jUsername, neo4jPassword))
    session = graph.session()
    nodes_string = session.run("MATCH (node { app_id:  \'" + str(appId) + "\' }) RETURN node,labels(node) as nodeType")
    nodes = [record for record in nodes_string.data()]
    session.close()
    return nodes


def get_graphRelationbyAppId(appId):
    graph = GraphDatabase.driver(uri="bolt://localhost:7687", auth=(neo4jUsername, neo4jPassword))
    session = graph.session()
    nodes_string = session.run("MATCH (client { app_id:  \'" + str(
        appId) + "\' }) -[relation]->(server) RETURN client,labels(client) as clientType, relation,TYPE(relation) as relationType,relation.protocol as protocol, server,labels(server) as serverType")
    nodes = [record for record in nodes_string.data()]
    session.close()
    return nodes


def get_graph():
    graph = GraphDatabase.driver(uri="bolt://127.0.0.1:7687", auth=(neo4jUsername, neo4jPassword))
    session = graph.session()
    return session


def macm_viewer(request, appId):
    return render(request, 'macm_viewer.html',{"appId":appId})


def threat_modeling(request, appId):
    # save assets info in sqlite
    nodes = Asset.objects.all().filter(app=MACM.objects.get(appId=appId))
    # connect to neo4j only if sqlite assets are empty (API are laggy)
    if not nodes:
        nodes = get_graphNodesbyAppId(appId)
        for node in nodes:
            # print(node)
            for nodeType in node["nodeType"]:
                Asset_type_instance = Asset_type.objects.filter(acronym=nodeType)
                if Asset_type_instance:
                    for assetType in Asset_type_instance:
                        Asset.objects.all().get_or_create(app=MACM.objects.get(appId=appId), asset_type=assetType,
                                                          name=node["node"]["name"])
    nodes = Asset.objects.all().filter(app=MACM.objects.get(appId=appId))
    # save relation info in sqlite

    archs = get_graphRelationbyAppId(appId)
    # print(archs)
    for arch in archs:
        Asset_client = Asset.objects.all().filter(name=arch["client"]["name"], app=MACM.objects.get(appId=appId))
        Asset_server = Asset.objects.all().filter(name=arch["server"]["name"], app=MACM.objects.get(appId=appId))

        if arch["protocol"] is None:
            print("returned list is None")
        elif isinstance(arch["protocol"], str):
            # single protocol in one arch
            try:
                print("asset " + str(Asset_client) + " protocol " + arch["protocol"] + " macm " +
                      str(MACM.objects.get(appId=appId)) + " relationType " + arch["relationType"] +
                      " role " + "client ")

                print("asset " + str(Asset_server) + " protocol " + arch["protocol"] + " macm " +
                      str(MACM.objects.get(appId=appId)) + " relationType " + arch["relationType"] +
                      " role " + "server ")

                Relation.objects.all().get_or_create(asset=Asset.objects.get(name=arch["client"]["name"],
                                                                             app=MACM.objects.get(appId=appId)),
                                                     protocol=Protocol.objects.get(protocol=arch["protocol"]),
                                                     app=MACM.objects.get(appId=appId),
                                                     relation_type=arch["relationType"],
                                                     role="client")
                Relation.objects.all().get_or_create(asset=Asset.objects.get(name=arch["server"]["name"],
                                                                             app=MACM.objects.get(appId=appId)),
                                                     protocol=Protocol.objects.get(protocol=arch["protocol"]),
                                                     app=MACM.objects.get(appId=appId),
                                                     relation_type=arch["relationType"],
                                                     role="server")
            except:
                print("Protocol info not found in arch between " + str(arch["client"]["name"]) + " and " + str(
                    arch["server"]["name"]))
        elif isinstance(arch["protocol"], list):
            for protocol in arch["protocol"]:
                print(protocol)
                # multiple protocol in one arch
                try:
                    Relation.objects.all().get_or_create(asset=Asset.objects.get(name=arch["client"]["name"],
                                                                                 app=MACM.objects.get(appId=appId)),
                                                         protocol=Protocol.objects.get(protocol=protocol),
                                                         app=MACM.objects.get(appId=appId),
                                                         relation_type=arch["relationType"],
                                                         role="client")
                    Relation.objects.all().get_or_create(asset=Asset.objects.get(name=arch["server"]["name"],
                                                                                 app=MACM.objects.get(appId=appId)),
                                                         protocol=Protocol.objects.get(protocol=protocol),
                                                         app=MACM.objects.get(appId=appId),
                                                         relation_type=arch["relationType"],
                                                         role="server")
                except:
                    print("Protocol info not found in arch between " + str(arch["client"]["name"]) + " and " + str(
                        arch["server"]["name"]))

            else:
                print("error getting protocol information")
            # we consider only relations with some associated properties
        relations = Relation.objects.all().filter(app=MACM.objects.get(appId=appId))
        for relation in relations:
            print(relation.asset.name)
        print("\n")

    return render(request, 'threat_modeling.html', {
        'nodes': nodes,
        'relations': relations
    })
