package secretrotation

import "sort"

// tallyInstances 按截止前最新一次回报统计达标/未达标实例数。达标判定
// 永远在需要时现算：只有“截止前收到且版本等于审计安全版本”的实例达标，
// 不持久化任何“已完成”标记，因此重部署/回报交错都不会沿用过时结论。
func tallyInstances(a *auditState) (complete, incomplete int) {
	for _, svc := range a.Services {
		for _, iv := range a.instancesOf(svc) {
			if instanceComplete(a, iv) {
				complete++
			} else {
				incomplete++
			}
		}
	}
	return complete, incomplete
}

// instancesOf 返回某服务在审计窗口内出现过的全部实例（按实例 ID 排序）。
// 这些实例即“服务当前已知实例集合”；审计发起之后才出现的实例同样纳入
// 判断，但必须凭自己的安全版本回报才能达标，不会被预先算作已完成。
func (a *auditState) instancesOf(service string) []InstanceAuditView {
	var out []InstanceAuditView
	for _, rec := range a.Instances {
		if rec.Service != service {
			continue
		}
		iv := InstanceAuditView{
			Service:        rec.Service,
			Instance:       rec.Instance,
			Version:        rec.Version,
			ReportedAt:     rec.ReportedAt,
			Replaces:       rec.Replaces,
			BeforeDeadline: !rec.ReportedAt.After(a.Deadline),
			Complete:       rec.Version == a.SafeVersion && !rec.ReportedAt.After(a.Deadline),
		}
		out = append(out, iv)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Instance < out[j].Instance })
	return out
}

func instanceComplete(a *auditState, iv InstanceAuditView) bool {
	return iv.BeforeDeadline && iv.Version == a.SafeVersion
}

// auditInfoView 由持久化状态现算审计的非敏感视图。
func auditInfoView(st *KeyState, a *auditState) *AuditInfo {
	out := &AuditInfo{
		KeyName:           st.Name,
		AuditID:           a.AuditID,
		Status:            a.Status,
		SafeVersion:       a.SafeVersion,
		Services:          cloneStrings(a.Services),
		Deadline:          a.Deadline,
		CreatedAt:         a.CreatedAt,
		ClosedAt:          a.ClosedAt,
		ClosedSafeVersion: a.ClosedSafeVersion,
		RevokedVersions:   revokedVersions(st),
	}
	for _, svc := range a.Services {
		views := a.instancesOf(svc)
		sv := ServiceAuditView{
			Name:               svc,
			CurrentSafeVersion: a.SafeVersion,
			RevokedVersions:    revokedVersions(st),
		}
		var last *InstanceAuditView
		for i := range views {
			iv := views[i]
			out.Instances = append(out.Instances, iv)
			if instanceComplete(a, iv) {
				sv.Complete = append(sv.Complete, iv)
			} else {
				sv.Incomplete = append(sv.Incomplete, iv)
			}
			if last == nil || iv.ReportedAt.After(last.ReportedAt) {
				cur := iv
				last = &cur
			}
		}
		sv.LastReport = last
		out.ServicesView = append(out.ServicesView, sv)
	}
	sort.Slice(out.Instances, func(i, j int) bool {
		if out.Instances[i].Service != out.Instances[j].Service {
			return out.Instances[i].Service < out.Instances[j].Service
		}
		return out.Instances[i].Instance < out.Instances[j].Instance
	})
	for _, is := range a.Issues {
		out.Issues = append(out.Issues, AuditIssueView{
			ID: is.ID, Service: is.Service, Instance: is.Instance,
			Version: is.Version, FoundAt: is.FoundAt,
		})
	}
	sort.Slice(out.Issues, func(i, j int) bool { return out.Issues[i].FoundAt.Before(out.Issues[j].FoundAt) })
	return out
}

// revokedVersions 返回已撤销（retired）版本号；grace 宽限版本同样是
// 被新版本取代、正在等待退役的“被撤销版本”，一并列出。
func revokedVersions(st *KeyState) []int {
	var out []int
	for _, v := range st.Versions {
		if v.Status == VersionRetired || v.Status == VersionGrace {
			out = append(out, v.Number)
		}
	}
	sort.Ints(out)
	return out
}
