import collections

import neo4j
from django.shortcuts import render, redirect
from neo4j import GraphDatabase
from project.settings import neo4jUser, neo4jPass, neo4jURI

neo4jUsername = neo4jUser
neo4jPassword = neo4jPass
neo4jUri = neo4jURI

from SlaGenerator.models import MACM, Asset, Relation, Protocol, Attribute, Attribute_value, Asset_Attribute_value, \
    Threat_Attribute_value


def apps_management(request):
    ordered_apps = []
    context = {}
    try:
        graphDriver = GraphDatabase.driver(uri=neo4jUri, auth=(neo4jUsername, neo4jPassword))
        session = graphDriver.session()
        nodes_string = session.run("match (node) return node")
        nodes = [record for record in nodes_string.data()]
        apps = {}
        for node in nodes:
            try:
                apps[node['node']['app_id']] = node['node']['application']
            except:
                print("Cannot parse graph with node " + str(node['node']))
        ordered_apps = collections.OrderedDict(sorted(apps.items()))
        #print(ordered_apps)
        for appId, application in ordered_apps.items():
            MACM_instance = MACM(appId=appId, application=application)
            MACMvalue = MACM.objects.all().filter(appId=appId, application=application)
            if not MACMvalue:
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
    graph = GraphDatabase.driver(uri=neo4jUri, auth=(neo4jUsername, neo4jPassword))
    session = graph.session()
    nodes_string = session.run("MATCH (node { app_id:  \'" + str(appId) + "\' }) RETURN "
                                                                          "node,labels(node) as nodeType")
    nodes = [record for record in nodes_string.data()]
    session.close()
    return nodes


def get_graphRelationbyAppId(appId):
    graph = GraphDatabase.driver(uri=neo4jUri, auth=(neo4jUsername, neo4jPassword))
    session = graph.session()
    nodes_string = session.run("MATCH (client { app_id:  \'" + str(
        appId) + "\' }) -[relation]->(server) RETURN client,labels(client) as clientType,"
                 " relation,TYPE(relation) as relationType,relation.protocol as protocol, "
                 "server,labels(server) as serverType")
    nodes = [record for record in nodes_string.data()]
    session.close()
    return nodes


def macm_viewer(request, appId):
    return render(request, 'macm_viewer.html', {"appId": appId})

def asset_management(request, appId):
    # save assets info in sqlite
    #nodes = Asset.objects.all().filter(app=MACM.objects.get(appId=appId))
    #metto nodes=None perchè così prende sempre fa neo4j (dovrei gestire la coerenza fra i due DB)
    nodes=None
    # connect to neo4j only if sqlite assets are empty (API are laggy)
    if not nodes:
        nodes = get_graphNodesbyAppId(appId)
        for node in nodes:
            #print(node["node"]["name"]+" "+ node["node"]["type"])
            # print(node)

            asset=Asset.objects.all().get_or_create(app=MACM.objects.get(appId=appId),
                                              name=node["node"]["name"])
            #mi salvo id sqlite in dizionario
            node['id'] = asset[0].id

            try:
                # vedo se il nome del componente è un attribute value
                # per il 5g andrebbero considerate le minacce sia di SERVICE.Web che di UE (ad esempio)
                Attribute_value_instance = Attribute_value.objects.get(attribute_value=node["node"]["type"])
                Asset_Attribute_value.objects.all().get_or_create(asset=asset[0],attribute_value=Attribute_value_instance)
                nodes = Asset_Attribute_value.objects.all().filter(app=MACM.objects.get(appId=appId))
            except:
                print()

    # save relation info in sqlite

    arches = get_graphRelationbyAppId(appId)
    for arch in arches:
        Asset_client = Asset.objects.all().filter(name=arch["client"]["name"], app=MACM.objects.get(appId=appId))
        Asset_server = Asset.objects.all().filter(name=arch["server"]["name"], app=MACM.objects.get(appId=appId))

        if arch["protocol"] is None:
            print()
        elif isinstance(arch["protocol"], str):
            # single protocol in one arch
            try:
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
                print()
                #print("Protocol info not found in arch between " + str(arch["client"]["name"]) + " and " + str(
                    #arch["server"]["name"]))
        elif isinstance(arch["protocol"], list):
            for protocol in arch["protocol"]:
                # print(protocol)
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
                    print()
                    #print("Protocol info not found in arch between " + str(arch["client"]["name"]) + " and " + str(
                     #   arch["server"]["name"]))
            else:
                print("error getting protocol information")
        # we consider only relations with some associated properties
        relations = Relation.objects.all().filter(app=MACM.objects.get(appId=appId))
    return render(request, 'asset_management.html', {
        'nodes': nodes,
        'relations': relations,
        'appId':appId
    })


def threat_modeling_per_asset(request, appId,assetId):
    asset=Asset.objects.all().filter(id=assetId)[0]
    asset_attribute_value=Asset_Attribute_value.objects.all().filter(asset_id=assetId)
    threats = Threat_Attribute_value.objects.all().filter(attribute_value_id=asset_attribute_value[0].attribute_value.id)



    return render(request, 'threat_modeling_per_asset.html', {
        'threats': threats,
        'asset':asset}
                  )

def threat_modeling(request, appId):
    threats_list=[]
    nodes = get_graphNodesbyAppId(appId)
    for node in nodes:
        asset = Asset.objects.all().filter(name=node["node"]["name"])[0]
        asset_attribute_value = Asset_Attribute_value.objects.all().filter(asset_id=asset.id)
        try:
            print(asset.name + " " + asset_attribute_value[0].attribute_value.attribute_value)
            threats = Threat_Attribute_value.objects.all().filter(attribute_value_id=asset_attribute_value[0].attribute_value.id)
            for threat in threats:
                if threat not in threats_list:
                    threats_list.append(threat)
        except:
            print()

        print(threats_list)


    return render(request, 'threat_modeling.html', {"threats":threats_list
        })
