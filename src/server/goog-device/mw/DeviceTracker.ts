import type WS from 'ws';
import { ACTION } from '../../../common/Action';
import { ChannelCode } from '../../../common/ChannelCode';
import { ControlCenterCommand } from '../../../common/ControlCenterCommand';
import type { Multiplexer } from '../../../packages/multiplexer/Multiplexer';
import type { DeviceTrackerEvent } from '../../../types/DeviceTrackerEvent';
import type { DeviceTrackerEventList } from '../../../types/DeviceTrackerEventList';
import type GoogDeviceDescriptor from '../../../types/GoogDeviceDescriptor';
import { Logger } from '../../Logger';
import { canAccessDevice } from '../../auth/deviceAccess';
import { Mw, type RequestParameters } from '../../mw/Mw';
import { ControlCenter } from '../services/ControlCenter';

export class DeviceTracker extends Mw {
    public static readonly TAG = 'DeviceTracker';
    private static readonly log = Logger.for('DeviceTracker');
    public static readonly type = 'android';
    private adt: ControlCenter = ControlCenter.getInstance();
    private readonly id: string;

    public static override processChannel(
        ws: Multiplexer,
        code: string,
        _data: ArrayBuffer | undefined,
        userId: number,
    ): Mw | undefined {
        if (code !== ChannelCode.GTRC) {
            return;
        }
        return new DeviceTracker(ws, userId);
    }

    public static override processRequest(ws: WS, params: RequestParameters): DeviceTracker | undefined {
        if (params.action !== ACTION.GOOG_DEVICE_LIST) {
            return;
        }
        return new DeviceTracker(ws, params.userId);
    }

    constructor(
        ws: WS | Multiplexer,
        private readonly userId: number,
    ) {
        super(ws);

        this.id = this.adt.getId();
        this.adt
            .init()
            .then(() => {
                this.adt.on('device', this.sendDeviceMessage);
                this.buildAndSendMessage(this.adt.getDevices().filter((device) => this.canAccess(device.udid)));
            })
            .catch((error: Error) => {
                DeviceTracker.log.error(error.message);
            });
    }

    private sendDeviceMessage = (device: GoogDeviceDescriptor): void => {
        if (!this.canAccess(device.udid)) return;
        const data: DeviceTrackerEvent<GoogDeviceDescriptor> = {
            device,
            id: this.id,
            name: this.adt.getName(),
        };
        this.sendMessage({
            id: -1,
            type: 'device',
            data,
        });
    };

    private canAccess(udid: string): boolean {
        return canAccessDevice(this.userId, udid);
    }

    private buildAndSendMessage = (list: GoogDeviceDescriptor[]): void => {
        const data: DeviceTrackerEventList<GoogDeviceDescriptor> = {
            list,
            id: this.id,
            name: this.adt.getName(),
        };
        this.sendMessage({
            id: -1,
            type: 'devicelist',
            data,
        });
    };

    protected onSocketMessage(event: WS.MessageEvent): void {
        let command: ControlCenterCommand;
        try {
            command = ControlCenterCommand.fromJSON(event.data.toString());
        } catch (error: any) {
            DeviceTracker.log.error(`Received message: ${event.data}. Error: ${error?.message}`);
            return;
        }
        if (!command.getUdid() || !this.canAccess(command.getUdid())) {
            DeviceTracker.log.error(`Denied device command for user ${this.userId}`);
            return;
        }
        this.adt.runCommand(command).catch((e) => {
            DeviceTracker.log.error(`Received message: ${event.data}. Error: ${e.message}`);
        });
    }

    public override release(): void {
        super.release();
        this.adt.off('device', this.sendDeviceMessage);
    }
}
