// Copyright 2021 The VPN House Authors. All rights reserved.
// Use of this source code is governed by a AGPL-style
// license that can be found in the LICENSE file.

package grpc

import (
	"context"
	"strconv"
	"strings"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/vpnhouse/tunnel/internal/admin"
	"github.com/vpnhouse/tunnel/proto"
)

type AdminServer struct {
	proto.AdminServiceServer
	AdminService *admin.Service
}

// Event implements proto.AdminServiceServer.
func (s *AdminServer) Event(ctx context.Context, event *proto.EventRequest) (*proto.EventResponse, error) {
	// Just check server time presence (not used for the moment)
	_, err := getServerTime(ctx)
	if err != nil {
		zap.L().Error("get server time failed", zap.Error(err))
	}

	// Event describes one of the dedicated action
	if event.GetAction().AddRestriction != nil {
		err := s.AdminService.AddRestriction(ctx, &admin.AddRestrictionRequest{
			UserId:         event.GetAction().GetAddRestriction().GetUserId(),
			InstallationId: event.GetAction().GetAddRestriction().GetInstallationId(),
			SessionId:      event.GetAction().GetAddRestriction().GetSessionId(),
			ExpiredTo:      event.GetAction().GetAddRestriction().GetRestrictTo(),
		})
		if err != nil {
			return nil, err
		}
	} else if event.GetAction().DeleteRestriction != nil {
		err := s.AdminService.DeleteRestriction(ctx, &admin.DeleteRestrictionRequest{
			UserId:         event.GetAction().GetDeleteRestriction().GetUserId(),
		})
		if err != nil {
			return nil, err
		}
	} else {
		return nil, status.Error(codes.InvalidArgument, "event has no action supplied")
	}
	return &proto.EventResponse{}, nil
}

func getServerTime(ctx context.Context) (int64, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return 0, status.Error(codes.DataLoss, "failed to get metadata")
	}
	serverTimeVals := md.Get("X-Server-Time")
	if len(serverTimeVals) != 1 {
		return 0, status.Errorf(codes.InvalidArgument, "missing 'X-Server-Time' header")
	}

	serverTime, err := strconv.ParseInt(strings.TrimSpace(serverTimeVals[0]), 10, 64)
	if err != nil {
		return 0, status.Errorf(codes.InvalidArgument, "'X-Server-Time' is not valid")
	}

	return serverTime, nil
}
