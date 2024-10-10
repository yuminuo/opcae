package opcae

import (
	"fmt"
	"github.com/huskar-t/opcda"
	"sync/atomic"
	"unsafe"

	"github.com/huskar-t/opcae/aecom"
	"golang.org/x/sys/windows/registry"

	"github.com/huskar-t/opcda/com"
	"golang.org/x/sys/windows"
)

type OPCEventServer struct {
	iServer                  *aecom.IOPCEventServer
	iCommon                  *com.IOPCCommon
	Name                     string
	Node                     string
	location                 com.CLSCTX
	clientSubscriptionHandle uint32
	eventSubscriptions       []*OPCEventSubscription
	browsers                 []*OPCAreaBrowser
}

func ConnectEventServer(progID, node string) (eventServer *OPCEventServer, err error) {
	location := com.CLSCTX_LOCAL_SERVER
	if !com.IsLocal(node) {
		location = com.CLSCTX_REMOTE_SERVER
	}
	var clsid *windows.GUID
	if location == com.CLSCTX_LOCAL_SERVER {
		id, err := windows.GUIDFromString(progID)
		if err != nil {
			return nil, err
		}
		clsid = &id
	} else {
		// try get clsid from server list
		clsid, err = getClsIDFromOldServerList(progID, node, location)
		if err != nil {
			// try get clsid from server list
			clsid, err = getClsIDFromServerList(progID, node, location)
			if err != nil {
				// try get clsid from windows reg
				clsid, err = getClsIDFromReg(progID, node)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	iUnknownServer, err := com.MakeCOMObjectEx(node, location, clsid, &aecom.IID_IOPCEventServer)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			iUnknownServer.Release()
		}
	}()
	var iUnknownCommon *com.IUnknown
	err = iUnknownServer.QueryInterface(&com.IID_IOPCCommon, unsafe.Pointer(&iUnknownCommon))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			iUnknownCommon.Release()
		}
	}()
	server := &aecom.IOPCEventServer{IUnknown: iUnknownServer}
	common := &com.IOPCCommon{IUnknown: iUnknownCommon}
	eventServer = &OPCEventServer{
		iServer:  server,
		iCommon:  common,
		Name:     progID,
		Node:     node,
		location: location,
	}
	return eventServer, nil
}

func (v *OPCEventServer) GetStatus() (*aecom.EventServerStatus, error) {
	return v.iServer.GetStatus()
}

// CreateEventSubscription
// active: FALSE if the Event Subscription is to be created inactive and TRUE if it is to be created as active.
// bufferTime: The requested buffer time. The buffer time is in milliseconds and tells the server how often to send event notifications. A value of 0 for dwBufferTime means that the server should send event notifications as soon as it gets them.
// maxSize: The requested maximum number of events that will be sent in a single IOPCEventSink::OnEvent callback. A value of 0 means that there is no limit to the number of events that will be sent in a single callback
func (v *OPCEventServer) CreateEventSubscription(active bool, bufferTime, maxSize, receiverBufSize uint32) (*OPCEventSubscription, uint32, uint32, error) {
	clientSubscriptionHandle := atomic.AddUint32(&v.clientSubscriptionHandle, 1)
	unknown, revisedBufferTime, revisedMaxSize, err := v.iServer.CreateEventSubscription(active, bufferTime, maxSize, clientSubscriptionHandle, &aecom.IID_IOPCEventSubscriptionMgt)
	if err != nil {
		return nil, 0, 0, err
	}
	sub, err := NewOPCEventSubscription(unknown, v.iCommon, clientSubscriptionHandle, receiverBufSize)
	if err != nil {
		return nil, 0, 0, err
	}
	return sub, revisedBufferTime, revisedMaxSize, nil
}

func (v *OPCEventServer) QueryAvailableFilters() ([]Filter, error) {
	filterMask, err := v.iServer.QueryAvailableFilters()
	if err != nil {
		return nil, err
	}
	return ParseFilter(filterMask), nil
}

type EventCategory struct {
	ID          uint32
	Description string
}

func (v *OPCEventServer) QueryEventCategories(categories []EventCategoryType) ([]*EventCategory, error) {
	category := MarshalEventCategoryType(categories)
	ids, descs, err := v.iServer.QueryEventCategories(category)
	if err != nil {
		return nil, err
	}
	result := make([]*EventCategory, len(ids))
	for i := range ids {
		result[i] = &EventCategory{
			ID:          ids[i],
			Description: descs[i],
		}
	}
	return result, nil
}

func (v *OPCEventServer) QueryConditionNames(categories []EventCategoryType) ([]string, error) {
	category := MarshalEventCategoryType(categories)
	return v.iServer.QueryConditionNames(category)
}

func (v *OPCEventServer) QuerySourceConditions(source string) ([]string, error) {
	return v.iServer.QuerySourceConditions(source)
}

func (v *OPCEventServer) QuerySubConditionNames(conditionName string) ([]string, error) {
	return v.iServer.QuerySubConditionNames(conditionName)
}

type EventAttribute struct {
	ID          uint32
	Description string
	Type        uint16
}

func (v *OPCEventServer) QueryEventAttributes(eventCategoryID uint32) ([]*EventAttribute, error) {
	ids, descs, types, err := v.iServer.QueryEventAttributes(eventCategoryID)
	if err != nil {
		return nil, err
	}
	result := make([]*EventAttribute, len(ids))
	for i := range ids {
		result[i] = &EventAttribute{
			ID:          ids[i],
			Description: descs[i],
			Type:        types[i],
		}
	}
	return result, nil
}

type ItemID struct {
	ID    string
	Name  string
	CLSID windows.GUID
}

func (v *OPCEventServer) TranslateToItemIDs(source string, eventCategoryID uint32, conditionName string, subConditionName string, assocAttrIDs []uint32) ([]*ItemID, error) {
	ids, names, clsIDs, err := v.iServer.TranslateToItemIDs(source, eventCategoryID, conditionName, subConditionName, assocAttrIDs)
	if err != nil {
		return nil, err
	}
	result := make([]*ItemID, len(ids))
	for i := range ids {
		result[i] = &ItemID{
			ID:    ids[i],
			Name:  names[i],
			CLSID: clsIDs[i],
		}
	}
	return result, nil
}

func (v *OPCEventServer) CreateAreaBrowser() (*OPCAreaBrowser, error) {
	unknown, err := v.iServer.CreateAreaBrowser(&aecom.IID_IOPCEventAreaBrowser)
	if err != nil {
		return nil, err
	}
	return NewOPCAreaBrowser(unknown), nil
}

func (v *OPCEventServer) Disconnect() error {
	for _, subscription := range v.eventSubscriptions {
		subscription.Release()
	}
	v.iServer.Release()
	return nil
}

func getClsIDFromServerList(progID, node string, location com.CLSCTX) (*windows.GUID, error) {
	iCatInfo, err := com.MakeCOMObjectEx(node, location, &com.CLSID_OpcServerList, &com.IID_IOPCServerList2)
	if err != nil {
		return nil, err
	}
	defer iCatInfo.Release()
	sl := &com.IOPCServerList2{IUnknown: iCatInfo}
	clsid, err := sl.CLSIDFromProgID(progID)
	if err != nil {
		return nil, err
	}
	return clsid, nil
}

func getClsIDFromOldServerList(progID, node string, location com.CLSCTX) (*windows.GUID, error) {
	iCatInfo, err := com.MakeCOMObjectEx(node, location, &com.CLSID_OpcServerList, &com.IID_IOPCServerList)
	if err != nil {
		return nil, err
	}
	defer iCatInfo.Release()
	sl := &com.IOPCServerList{IUnknown: iCatInfo}
	clsid, err := sl.CLSIDFromProgID(progID)
	if err != nil {
		return nil, err
	}
	return clsid, nil
}

func getClsIDFromReg(progID, node string) (*windows.GUID, error) {
	var clsid windows.GUID
	var err error
	hKey, err := registry.OpenRemoteKey(node, registry.CLASSES_ROOT)
	if err != nil {
		return nil, err
	}
	defer hKey.Close()
	hProgIDKey, err := registry.OpenKey(hKey, progID, registry.READ)
	if err != nil {
		return nil, err
	}
	defer hProgIDKey.Close()
	hClsidKey, err := registry.OpenKey(hProgIDKey, "CLSID", registry.READ)
	if err != nil {
		return nil, err
	}
	defer hClsidKey.Close()
	clsidStr, _, err := hClsidKey.GetStringValue("")
	if err != nil {
		return nil, err
	}
	clsid, err = windows.GUIDFromString(clsidStr)
	return &clsid, err
}

// GetOPCEventServers get OPC Event servers from node
func GetOPCEventServers(node string) ([]*opcda.ServerInfo, error) {
	location := com.CLSCTX_LOCAL_SERVER
	if !com.IsLocal(node) {
		location = com.CLSCTX_REMOTE_SERVER
	}
	iCatInfo, err := com.MakeCOMObjectEx(node, location, &com.CLSID_OpcServerList, &com.IID_IOPCServerList2)
	if err != nil {
		return nil, opcda.NewOPCWrapperError("make com object IOPCServerList2", err)
	}
	cids := []windows.GUID{aecom.IID_CATID_OPCEventServer}
	defer iCatInfo.Release()
	sl := &com.IOPCServerList2{IUnknown: iCatInfo}
	iEnum, err := sl.EnumClassesOfCategories(cids, nil)
	if err != nil {
		return nil, opcda.NewOPCWrapperError("server list EnumClassesOfCategories", err)
	}
	defer iEnum.Release()
	var result []*opcda.ServerInfo
	for {
		var classID windows.GUID
		var actual uint32
		err = iEnum.Next(1, &classID, &actual)
		if err != nil {
			break
		}
		server, err := getServer(sl, &classID)
		if err != nil {
			return nil, opcda.NewOPCWrapperError("getServer", err)
		}
		result = append(result, server)
	}
	return result, nil
}

func GetOPCOldEventServers(node string) ([]*opcda.OldServerInfo, error) {
	location := com.CLSCTX_LOCAL_SERVER
	if !com.IsLocal(node) {
		location = com.CLSCTX_REMOTE_SERVER
	}
	iCatInfo, err := com.MakeCOMObjectEx(node, location, &com.CLSID_OpcServerList, &com.IID_IOPCServerList)
	if err != nil {
		return nil, opcda.NewOPCWrapperError("make com object IOPCServerList", err)
	}
	cids := []windows.GUID{aecom.IID_CATID_OPCEventServer}
	defer iCatInfo.Release()
	sl := &com.IOPCServerList{IUnknown: iCatInfo}
	iEnum, err := sl.EnumClassesOfCategories(cids, nil)
	if err != nil {
		return nil, opcda.NewOPCWrapperError("server list EnumClassesOfCategories", err)
	}
	defer iEnum.Release()
	var result []*opcda.OldServerInfo
	for {
		var classID windows.GUID
		var actual uint32
		err = iEnum.Next(1, &classID, &actual)
		if err != nil {
			break
		}
		server, err := getOldServer(sl, &classID)
		if err != nil {
			return nil, opcda.NewOPCWrapperError("getOldServer", err)
		}
		result = append(result, server)
	}
	return result, nil
}

func getServer(sl *com.IOPCServerList2, classID *windows.GUID) (*opcda.ServerInfo, error) {
	progID, userType, VerIndProgID, err := sl.GetClassDetails(classID)
	if err != nil {
		return nil, fmt.Errorf("FAILED to get prog ID from class ID: %w", err)
	}
	defer func() {
		com.CoTaskMemFree(unsafe.Pointer(progID))
		com.CoTaskMemFree(unsafe.Pointer(userType))
		com.CoTaskMemFree(unsafe.Pointer(VerIndProgID))
	}()
	clsStr := classID.String()
	return &opcda.ServerInfo{
		ProgID:       windows.UTF16PtrToString(progID),
		ClsStr:       clsStr,
		ClsID:        classID,
		VerIndProgID: windows.UTF16PtrToString(VerIndProgID),
	}, nil
}

func getOldServer(sl *com.IOPCServerList, classID *windows.GUID) (*opcda.OldServerInfo, error) {
	progID, userType, err := sl.GetClassDetails(classID)
	if err != nil {
		return nil, fmt.Errorf("FAILED to get prog ID from class ID: %w", err)
	}
	defer func() {
		com.CoTaskMemFree(unsafe.Pointer(progID))
		com.CoTaskMemFree(unsafe.Pointer(userType))
	}()
	clsStr := classID.String()
	return &opcda.OldServerInfo{
		ProgID: windows.UTF16PtrToString(progID),
		ClsStr: clsStr,
		ClsID:  classID,
	}, nil
}
