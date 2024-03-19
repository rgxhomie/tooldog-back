import { Controller, Post, UseGuards, Headers, Body, Param, Query } from '@nestjs/common';
import { AuthGuard } from 'src/auth/auth.guard';

@Controller('test')
export class TestController {

    @Post()
    // @UseGuards(AuthGuard)
    async testPostHandler(
        @Headers() headers, 
        @Query() params,
        @Body() body,
    ) {
        return {success: true, headers, body, params}
    }
}
